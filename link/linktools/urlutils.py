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

__all__ = ("make_url", "cookie_to_dict", "guess_file_name", "user_agent",
           "DownloadError", "UrlFile",
           "NotFoundVersion", "get_chrome_driver",)

import cgi
import contextlib
import json
import os
import shelve
import shutil
from typing import Dict, Union, List, Tuple
from urllib import parse

from filelock import FileLock
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
    TimeRemainingColumn, TransferSpeedColumn,
)

from . import utils
from ._environ import resource, config, tools
from ._logger import get_logger
from .decorator import cached_property

logger = get_logger("urlutils")

DataType = Union[str, int, float]
QueryType = Union[DataType, List[DataType], Tuple[DataType]]

_user_agent = None


def user_agent(style=None) -> str:
    try:
        from .reference.fake_useragent import UserAgent, VERSION

        global _user_agent
        if (not _user_agent) and style:
            _user_agent = UserAgent(
                path=resource.get_path(f"fake_useragent_{VERSION}.json")
            )

        if style:
            return _user_agent[style]

        return _user_agent.random

    except Exception as e:
        logger.debug(f"fetch user agent error: {e}")

    return config["SETTING_DOWNLOAD_USER_AGENT"]


def make_url(url: str, *paths: str, **kwargs: QueryType) -> str:
    result = url

    for path in paths:
        result = result.rstrip("/") + "/" + path.lstrip("/")

    if len(kwargs) > 0:
        queries = []
        for key, value in kwargs.items():
            if isinstance(value, (list, tuple)):
                queries.extend((key, v) for v in value)
            else:
                queries.append((key, value))

        result = result + "?" + parse.urlencode(queries)

    return result


def cookie_to_dict(cookie: str) -> Dict[str, str]:
    cookies = {}
    for item in cookie.split(';'):
        key_value = item.split('=', 1)
        cookies[key_value[0].strip()] = key_value[1].strip() if len(key_value) > 1 else ''
    return cookies


def guess_file_name(url: str) -> str:
    return os.path.split(parse.urlparse(url).path)[1]


class DownloadError(Exception):
    pass


# noinspection PyProtectedMember,SpellCheckingInspection
class _ContextVar(property):

    def __init__(self, key, default=None):
        def fget(o: "_Context"):
            return o._db.get(key, default)

        def fset(o: "_Context", v):
            o._db[key] = v

        super().__init__(fget=fget, fset=fset)


class _Context:
    url: str = _ContextVar("url")
    user_agent: str = _ContextVar("user_agent")
    headers: dict = _ContextVar("headers")
    file_path: str = _ContextVar("file_path")
    file_size: int = _ContextVar("file_size")
    file_name: str = _ContextVar("file_name")
    completed: bool = _ContextVar("completed", False)

    def __init__(self, path: str):
        self._db = shelve.open(path)

    def __enter__(self):
        self._db.__enter__()
        return self

    def __exit__(self, *args, **kwargs):
        self._db.__exit__(*args, **kwargs)


class UrlFile:

    def __init__(self, url: str):
        self._url = url
        self._ident = f"{utils.get_md5(url)}_{guess_file_name(url)[-100:]}"
        self._root_path = resource.get_temp_path("download", self._ident)
        self._file_path = os.path.join(self._root_path, "file")
        self._context_path = os.path.join(self._root_path, "context")

    @cached_property
    def _lock(self) -> FileLock:
        # noinspection PyTypeChecker
        return FileLock(
            resource.get_temp_path("download", "lock", self._ident, create_parent=True)
        )

    def save(self, save_dir: str = None, save_name: str = None, timeout: int = None, **kwargs) -> str:
        """
        从指定url下载文件
        :param save_dir: 文件路径，如果为空，则保存到temp目录
        :param save_name: 文件名，如果为空，则默认为下载的文件名
        :param timeout: 超时时间
        :return: 文件路径
        """

        lock = self._lock
        target_path = self._file_path
        timeout_meter = utils.TimeoutMeter(timeout)

        try:
            lock.acquire(timeout=timeout_meter.get(), poll_interval=1)

            if not os.path.exists(self._root_path):
                os.makedirs(self._root_path)

            with _Context(self._context_path) as context:

                if os.path.exists(self._file_path) and context.completed:
                    # 下载完成了，那就不用再下载了
                    logger.debug(f"{self._file_path} downloaded, skip")

                else:
                    # 初始化环境信息
                    context.url = self._url
                    context.file_path = self._file_path
                    context.file_size = None

                    if not context.file_name:
                        context.file_name = save_name or guess_file_name(self._url)
                    if not context.user_agent:
                        context.user_agent = kwargs.pop("user_agent", None) or user_agent("chrome")

                    # 开始下载
                    context.completed = False
                    self._download(context, timeout_meter)
                    context.completed = True

                if save_dir:
                    # 如果指定了路径，先创建路径
                    if not os.path.exists(save_dir):
                        logger.debug(f"{save_dir} does not exist, create")
                        os.makedirs(save_dir)

                    # 然后把文件保存到指定路径下
                    target_path = os.path.join(save_dir, save_name or context.file_name)
                    logger.debug(f"Rename {self._file_path} to {target_path}")
                    os.rename(self._file_path, target_path)

                    # 把文件移动到指定目录之后，就可以清理缓存文件了
                    self.clear(timeout=timeout_meter.get())

        except DownloadError as e:
            raise e

        except Exception as e:
            raise DownloadError(e)

        finally:
            utils.ignore_error(lock.release)

        return target_path

    def clear(self, timeout: int = None):
        """
        清空缓存文件
        """
        lock = self._lock
        with lock.acquire(timeout):
            if not os.path.exists(self._root_path):
                logger.debug(f"{self._root_path} does not exist, skip")
                return
            logger.debug(f"Clear {self._root_path}")
            if os.path.exists(self._file_path):
                os.remove(self._file_path)
            if os.path.exists(self._context_path):
                os.remove(self._context_path)
            if not os.listdir(self._root_path):
                shutil.rmtree(self._root_path, ignore_errors=True)

    def __enter__(self):
        self._lock.acquire()
        return self

    def __exit__(self, *args, **kwargs):
        self._lock.release()

    @classmethod
    def _download(cls, context: _Context, timeout_meter: utils.TimeoutMeter):
        logger.debug(f"Download file to temp path {context.file_path}")

        initial = 0
        # 如果文件存在，则继续上一次下载
        if os.path.exists(context.file_path):
            size = os.path.getsize(context.file_path)
            logger.debug(f"{size} bytes downloaded, continue")
            initial = size

        context.headers = {
            "User-Agent": context.user_agent,
            "Range": f"bytes={initial}-",
        }

        progress = Progress(
            SpinnerColumn(),
            "{task.description}",
            BarColumn(),
            DownloadColumn(),
            TransferSpeedColumn(),
            "·",
            TaskProgressColumn(),
            "· elapsed",
            TimeElapsedColumn(),
            "· remaining",
            TimeRemainingColumn(),
        )

        try:
            import requests
            download_fn = cls._download_with_requests
        except ModuleNotFoundError:
            download_fn = cls._download_with_urllib

        with progress:
            task_id = progress.add_task(context.file_name, total=initial + 1)
            progress.advance(task_id, initial)

            with open(context.file_path, 'ab') as fp:
                offset = 0
                for data in download_fn(context, timeout_meter.get()):
                    advance = len(data)
                    offset += advance
                    fp.write(data)
                    progress.update(
                        task_id,
                        advance=advance,
                        description=context.file_name
                    )
                    if context.file_size is not None:
                        progress.update(
                            task_id,
                            total=initial + context.file_size
                        )

            if context.file_size is not None and context.file_size > offset:
                raise DownloadError(
                    f"download size {initial + context.file_size} bytes was expected,"
                    f" got {initial + offset} bytes"
                )

            if os.path.getsize(context.file_path) == 0:
                raise DownloadError(f"download {context.url} error")

    @classmethod
    def _download_with_requests(cls, context: _Context, timeout: float):
        import requests

        bs = 1024 * 8

        with requests.get(context.url, headers=context.headers, stream=True, timeout=timeout) as resp:

            resp.raise_for_status()

            if "Content-Length" in resp.headers:
                context.file_size = int(resp.headers.get("Content-Length"))
            if "Content-Disposition" in resp.headers:
                _, params = cgi.parse_header(resp.headers["Content-Disposition"])
                if "filename" in params:
                    context.file_name = params["filename"]

            for chunk in resp.iter_content(bs):
                if chunk:
                    yield chunk

    @classmethod
    def _download_with_urllib(cls, context: _Context, timeout: float):
        from urllib.request import urlopen, Request

        bs = 1024 * 8

        url = Request(context.url, headers=context.headers)
        with contextlib.closing(urlopen(url=url, timeout=timeout)) as fp:

            headers = fp.info()
            if "Content-Length" in headers:
                context.file_size = int(headers["Content-Length"])
            if "Content-Disposition" in headers:
                _, params = cgi.parse_header(headers["Content-Disposition"])
                if "filename" in params:
                    context.file_name = params["filename"]

            while True:
                chunk = fp.read(bs)
                if not chunk:
                    break
                yield chunk


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
