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
   /  oooooooooooooooo  .o.  oooo /,   `,"-----------
  / ==ooooooooooooooo==.o.  ooo= //   ,``--{)B     ,"
 /_==__==========__==_ooo__ooo=_/'   /___________,"
"""

import contextlib
import os
import shelve
import shutil
from typing import TYPE_CHECKING

from .decorator import cached_property
from .rich import create_progress
from .utils import get_md5, ignore_error, timeoutable, parse_header, guess_file_name, user_agent

if TYPE_CHECKING:
    from ._environ import BaseEnviron
    from .utils import Timeout


class DownloadError(Exception):
    pass


class DownloadHttpError(DownloadError):

    def __init__(self, code, e):
        super().__init__(e)
        self.code = code


class DownloadContextVar(property):

    def __init__(self, key, default=None):
        def fget(o: "DownloadContext"):
            return o._db.get(key, default)

        def fset(o: "DownloadContext", v):
            o._db[key] = v

        super().__init__(fget=fget, fset=fset)


class DownloadContext:
    url: str = DownloadContextVar("Url")
    user_agent: str = DownloadContextVar("UserAgent")
    headers: dict = DownloadContextVar("Headers")
    file_path: str = DownloadContextVar("FilePath")
    file_size: int = DownloadContextVar("FileSize")
    file_name: str = DownloadContextVar("FileName")
    completed: bool = DownloadContextVar("IsCompleted", False)

    def __init__(self, environ: "BaseEnviron", path: str):
        self._environ = environ
        self._db = shelve.open(path)

    def __enter__(self):
        self._db.__enter__()
        return self

    def __exit__(self, *args, **kwargs):
        self._db.__exit__(*args, **kwargs)

    def download(self, timeout: "Timeout"):
        self._environ.logger.debug(f"Download file to temp path {self.file_path}")

        initial = 0
        # 如果文件存在，则继续上一次下载
        if os.path.exists(self.file_path):
            size = os.path.getsize(self.file_path)
            self._environ.logger.debug(f"{size} bytes downloaded, continue")
            initial = size

        self.headers = {
            "User-Agent": self.user_agent,
            "Range": f"bytes={initial}-",
        }

        try:
            import requests
            fn = self._download_with_requests
        except ModuleNotFoundError:
            fn = self._download_with_urllib

        with create_progress() as progress:
            task_id = progress.add_task(self.file_name, total=None)
            progress.advance(task_id, initial)

            with open(self.file_path, "ab") as fp:
                offset = 0
                for data in fn(timeout.remain):
                    advance = len(data)
                    offset += advance
                    fp.write(data)
                    progress.update(
                        task_id,
                        advance=advance,
                        description=self.file_name
                    )
                    if self.file_size is not None:
                        progress.update(
                            task_id,
                            total=initial + self.file_size
                        )

            if self.file_size is not None and self.file_size > offset:
                raise DownloadError(
                    f"download size {initial + self.file_size} bytes was expected, "
                    f"got {initial + offset} bytes"
                )

            if os.path.getsize(self.file_path) == 0:
                raise DownloadError(f"download {self.url} error")

    def _download_with_requests(self, timeout: float):
        import requests
        from requests import HTTPError

        bs = 1024 * 8

        with requests.get(self.url, headers=self.headers, stream=True, timeout=timeout) as resp:

            try:
                resp.raise_for_status()
            except HTTPError as e:
                raise DownloadHttpError(resp.status_code, e)

            if "Content-Length" in resp.headers:
                self.file_size = int(resp.headers.get("Content-Length"))
            if "Content-Disposition" in resp.headers:
                _, params = parse_header(resp.headers["Content-Disposition"])
                if "filename" in params:
                    self.file_name = params["filename"]

            for chunk in resp.iter_content(bs):
                if chunk:
                    yield chunk

    def _download_with_urllib(self, timeout: float):
        from urllib.request import urlopen, Request
        from urllib.error import HTTPError

        bs = 1024 * 8

        url = Request(self.url, headers=self.headers)

        try:
            resp = urlopen(url=url, timeout=timeout)
        except HTTPError as e:
            raise DownloadHttpError(e.code, e)

        with contextlib.closing(resp) as fp:

            headers = fp.info()
            if "Content-Length" in headers:
                self.file_size = int(headers["Content-Length"])
            if "Content-Disposition" in headers:
                _, params = parse_header(headers["Content-Disposition"])
                if "filename" in params:
                    self.file_name = params["filename"]

            while True:
                chunk = fp.read(bs)
                if not chunk:
                    break
                yield chunk


class UrlFile:

    def __init__(self, environ: "BaseEnviron", url: str):
        self._url = url
        self._environ = environ
        self._ident = f"{get_md5(url)}_{guess_file_name(url)[-100:]}"
        self._root_path = self._environ.get_temp_path("download", self._ident)
        self._temp_path = os.path.join(self._root_path, "file")
        self._context_path = os.path.join(self._root_path, "context")

    @cached_property
    def _lock(self):
        from filelock import FileLock
        return FileLock(
            self._environ.get_temp_path("download", "lock", self._ident, create_parent=True)
        )

    @timeoutable
    def _download(self, context: DownloadContext, retry: int, timeout: "Timeout", **kwargs) -> str:
        if os.path.exists(self._temp_path) and context.completed:
            # 下载完成了，那就不用再下载了
            self._environ.logger.debug(f"{self._temp_path} downloaded, skip")

        else:
            # 初始化环境信息
            context.url = self._url
            context.file_path = self._temp_path
            context.file_size = None
            context.completed = False

            if not context.file_name:
                context.file_name = guess_file_name(self._url)
            if not context.user_agent:
                context.user_agent = kwargs.pop("user_agent", None) or user_agent("chrome")

            # 开始下载
            last_error = None
            max_times = 1 + max(retry or 0, 0)
            for i in range(max_times, 0, -1):
                try:
                    if last_error is not None:
                        self._environ.logger.warning(
                            f"Download retry {max_times - i}, "
                            f"{last_error.__class__.__name__}: {last_error}")
                    context.download(timeout)
                    context.completed = True
                    break
                except Exception as e:
                    last_error = e

            if not context.completed:
                raise last_error

        return self._temp_path

    @timeoutable
    def download(self, retry: int = 2, timeout: "Timeout" = None, **kwargs) -> str:
        """
        从指定url下载文件到临时目录
        :param timeout: 超时时间
        :param retry: 重试次数
        :return: 文件路径
        """

        try:
            self._lock.acquire(timeout=timeout.remain, poll_interval=1)

            if not os.path.exists(self._root_path):
                os.makedirs(self._root_path, exist_ok=True)

            with DownloadContext(self._environ, self._context_path) as context:
                temp_path = self._download(context, retry, timeout, **kwargs)

            return temp_path

        except DownloadError:
            raise

        except Exception as e:
            raise DownloadError(e)

        finally:
            ignore_error(self._lock.release)

    @timeoutable
    def save(self, dir: str, name: str = None, timeout: "Timeout" = None, retry: int = 2, **kwargs) -> str:
        """
        从指定url下载文件
        :param dir: 文件路径
        :param name: 文件名，如果为空，则默认为下载的文件名
        :param timeout: 超时时间
        :param retry: 重试次数
        :return: 文件路径
        """

        try:
            self._lock.acquire(timeout=timeout.remain, poll_interval=1)

            if not os.path.exists(self._root_path):
                os.makedirs(self._root_path, exist_ok=True)

            with DownloadContext(self._environ, self._context_path) as context:
                temp_path = self._download(context, retry, timeout, **kwargs)

                # 先创建文件夹
                if not os.path.exists(dir):
                    self._environ.logger.debug(f"{dir} does not exist, create")
                    os.makedirs(dir)

                # 然后把文件保存到指定路径下
                target_path = os.path.join(dir, name or context.file_name)
                self._environ.logger.debug(f"Rename {temp_path} to {target_path}")
                os.rename(temp_path, target_path)

                # 把文件移动到指定目录之后，就可以清理缓存文件了
                self.clear(timeout=timeout.remain)

                return target_path

        except DownloadError:
            raise

        except Exception as e:
            raise DownloadError(e)

        finally:
            ignore_error(self._lock.release)

    @timeoutable
    def clear(self, timeout: "Timeout" = None):
        """
        清空缓存文件
        """
        lock = self._lock
        with lock.acquire(timeout.remain):
            if not os.path.exists(self._root_path):
                self._environ.logger.debug(f"{self._root_path} does not exist, skip")
                return
            self._environ.logger.debug(f"Clear {self._root_path}")
            if os.path.exists(self._temp_path):
                os.remove(self._temp_path)
            if os.path.exists(self._context_path):
                os.remove(self._context_path)
            if not os.listdir(self._root_path):
                shutil.rmtree(self._root_path, ignore_errors=True)

    def __enter__(self):
        self._lock.acquire()
        return self

    def __exit__(self, *args, **kwargs):
        self._lock.release()
