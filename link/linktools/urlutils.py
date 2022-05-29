#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : _download.py 
@time    : 2022/05/28
@site    :  
@software: PyCharm 

              ,----------------,              ,---------,
         ,-----------------------,          ,"        ,"|
       ,"                      ,"|        ,"        ,"  |
      +-----------------------+  |      ,"        ,"    |
      |  .-----------------.  |  |     +---------+      |
      |  |                 |  |  |     | -==----'|      |
      |  | $ sudo rm -rf / |  |  |     |         |      |
      |  |                 |  |  |/----|`---=    |      |
      |  |                 |  |  |   ,/|==== ooo |      ;
      |  |                 |  |  |  // |(((( [33]|    ,"
      |  `-----------------'  |," .;'| |((((     |  ,"
      +-----------------------+  ;;  | |         |,"
         /_)______________(_/  //'   | +---------+
    ___________________________/___  `,
   /  oooooooooooooooo  .o.  oooo /,   \,"-----------
  / ==ooooooooooooooo==.o.  ooo= //   ,`\--{)B     ,"
 /_==__==========__==_ooo__ooo=_/'   /___________,"
"""

__all__ = ("make_url", "cookie_to_dict", "guess_file_name",
           "DownloadError", "UrlFile",
           "NotFoundVersion", "get_chrome_driver",)

import contextlib
import json
import os
import re
import shelve
from typing import Dict, Any

from filelock import FileLock
from tqdm import tqdm

from . import utils
from ._environ import resource, config, tools
from ._logger import get_logger
from .decorator import locked_cached_property

logger = get_logger("urlutils")

KEY_URL = "url"
KEY_FILE_SIZE = "file_size"
KEY_FILE_NAME = "file_name"
KEY_FILE_DOWNLOADED = "file_downloaded"
KEY_USER_AGENT = "user_agent"
KEY_HEADERS = "headers"


def make_url(url: str, path: str, **kwargs: Any) -> str:
    from urllib import parse
    result = url.rstrip("/") + "/" + path.lstrip("/")
    if len(kwargs) > 0:
        query_string = "&".join([f"{parse.quote(k)}={parse.quote(str(v))}" for k, v in kwargs.items()])
        result = result + "?" + query_string
    return result


def cookie_to_dict(cookie: str) -> Dict[str, str]:
    cookies = {}
    for item in cookie.split(';'):
        key_value = item.split('=', 1)
        cookies[key_value[0].strip()] = key_value[1].strip() if len(key_value) > 1 else ''
    return cookies


def guess_file_name(url: str) -> str:
    from urllib.parse import urlparse
    return os.path.split(urlparse(url).path)[1]


class DownloadError(Exception):
    pass


class UrlFile:

    def __init__(self, url: str):
        self._url = url
        self._root_path = resource.get_temp_path("download", "{}_{}_{}".format(
            utils.get_md5(url),
            utils.get_sha1(url),
            guess_file_name(url)[-100:]
        ))
        self._lock_path = os.path.join(self._root_path, "lock")
        self._file_path = os.path.join(self._root_path, "file")
        self._context_path = os.path.join(self._root_path, "context")

    @locked_cached_property
    def lock(self) -> FileLock:
        """
        获取文件锁
        :return: 文件锁
        """
        if not os.path.exists(self._root_path):
            logger.debug(f"Directory does not exist, create {self._root_path}")
            os.makedirs(self._root_path)
        return FileLock(self._lock_path)

    def save(self,
             save_dir: str = None, save_name: str = None,
             lock: FileLock = None, timeout: int = None,
             **kwargs) -> str:
        """
        从指定url下载文件
        :param save_dir: 文件路径，如果为空，则保存到temp目录
        :param save_name: 文件名，如果为空，则默认为下载的文件名
        :param timeout: 超时时间
        :param lock: 文件锁
        :return: 文件路径
        """

        target_path = self._file_path
        timeout_meter = utils.TimeoutMeter(timeout)

        if not lock:
            lock = self.lock

        try:
            lock.acquire(timeout=timeout_meter.get(), poll_interval=1)

            with shelve.open(self._context_path) as context:

                if os.path.exists(self._file_path) and context.get(KEY_FILE_DOWNLOADED, False):
                    # 下载完成了，那就不用再下载了
                    logger.debug(f"{self._file_path} downloaded, skip")
                else:
                    # 初始化环境信息
                    context[KEY_URL] = self._url
                    context[KEY_FILE_DOWNLOADED] = False
                    context[KEY_FILE_NAME] = save_name or guess_file_name(self._url)
                    context[KEY_USER_AGENT] = kwargs.get(KEY_USER_AGENT) or config["SETTING_DOWNLOAD_USER_AGENT"]
                    # 正式下载开始
                    self._download(context, timeout_meter)
                    # 下载完成后，把状态位标记成True
                    context[KEY_FILE_DOWNLOADED] = True

                if save_dir:
                    # 如果指定了路径，先创建路径
                    if not os.path.exists(save_dir):
                        logger.debug(f"Directory does not exist, create {save_dir}")
                        os.makedirs(save_dir)

                    # 然后把文件保存到指定路径下
                    target_path = os.path.join(save_dir, save_name or context[KEY_FILE_NAME])
                    logger.debug(f"Rename {self._file_path} to {target_path}")
                    os.rename(self._file_path, target_path)

                    # 把文件移动到指定目录之后，就可以清理缓存文件了
                    self.clear(lock, timeout_meter.get())

        except DownloadError as e:
            raise e

        except Exception as e:
            raise DownloadError(e)

        finally:
            utils.ignore_error(lock.release)

        return target_path

    def clear(self, lock: FileLock = None, timeout: int = None):
        """
        清空缓存文件
        """
        lock = lock or self.lock
        with lock.acquire(timeout):
            logger.debug(f"Clear download path: {self._root_path}")
            if os.path.exists(self._file_path):
                os.remove(self._file_path)
            if os.path.exists(self._context_path):
                os.remove(self._context_path)

    def __enter__(self):
        self.lock.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.lock.release()

    def _download(self, context, timeout_meter):
        logger.debug(f"Download file to temp path {self._file_path}")

        offset = 0
        # 如果文件存在，则继续上一次下载
        if os.path.exists(self._file_path):
            size = os.path.getsize(self._file_path)
            logger.debug(f"{size} bytes downloaded, continue")
            offset = size

        context[KEY_HEADERS] = {
            "User-Agent": context[KEY_USER_AGENT],
            "Range": f"bytes={offset}-",
        }

        with tqdm(unit='B', initial=offset, unit_scale=True, miniters=1, desc=context[KEY_FILE_NAME]) as t:

            try:
                import requests
                download_fn = self._download_with_requests
            except ModuleNotFoundError:
                download_fn = self._download_with_urllib

            for name, total, read in download_fn(context, timeout_meter.get()):
                if total is not None:
                    t.total = offset + total
                if name is not None:
                    t.desc = name
                t.update(offset + read - t.n)

            if t.total is not None and t.total > t.n:
                raise DownloadError(f"download size {t.total} bytes was expected, got {t.n} bytes")

            if os.path.getsize(self._file_path) == 0:
                raise DownloadError(f"download {self._url} error")

    def _download_with_requests(self, context, timeout):
        import requests

        bs = 1024 * 8
        name = None
        total = None
        read = 0
        yield name, total, read

        with requests.get(self._url, headers=context[KEY_HEADERS], stream=True, timeout=timeout) as resp:

            if "Content-Length" in resp.headers:
                context[KEY_FILE_SIZE] = total = int(resp.headers.get("Content-Length"))
            if "Content-Disposition" in resp.headers:
                groups = re.findall("filename=(.+)", resp.headers.get("Content-Disposition"))
                if len(groups) > 0:
                    context[KEY_FILE_NAME] = name = groups[0]

            with open(self._file_path, 'ab') as tfp:
                yield name, total, read
                for chunk in resp.iter_content(bs):
                    if chunk:
                        read += len(chunk)
                        tfp.write(chunk)
                        yield name, total, read

    def _download_with_urllib(self, context, timeout):
        from urllib.request import urlopen, Request

        bs = 1024 * 8
        name = None
        total = None
        read = 0
        yield name, total, read

        url = Request(self._url, headers=context[KEY_HEADERS])
        with contextlib.closing(urlopen(url=url, timeout=timeout)) as fp:

            response_headers = fp.info()
            if "Content-Length" in response_headers:
                context[KEY_FILE_SIZE] = total = int(response_headers["Content-Length"])
            if "Content-Disposition" in response_headers:
                groups = re.findall("filename=(.+)", response_headers["Content-Disposition"])
                if len(groups) > 0:
                    context[KEY_FILE_SIZE] = name = groups[0]

            with open(self._file_path, "ab") as tfp:
                yield name, total, read
                while True:
                    chunk = fp.read(bs)
                    if not chunk:
                        break
                    read += len(chunk)
                    tfp.write(chunk)
                    yield name, total, read


class NotFoundVersion(Exception):
    pass


def get_chrome_driver(version: str):
    chrome_driver = tools["chromedriver80"]
    base_url = chrome_driver.config.get("base_url")

    def split_version(v):
        return tuple(int(i) for i in v.split("."))

    versions = split_version(version)
    if versions[0] >= 70:
        file = UrlFile(f"{base_url}/LATEST_RELEASE_{versions[0]}")
        with open(file.save(), "rt") as fd:
            return chrome_driver.copy(version=fd.read())

    path = resource.get_path("chrome-driver.json")
    with open(path, "rt") as fd:
        version_map = json.load(fd)

    for key, value in version_map.items():
        if versions[0] == split_version(value)[0]:
            return chrome_driver.copy(version=key)

    raise NotFoundVersion(version)
