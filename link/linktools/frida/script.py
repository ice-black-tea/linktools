#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : script.py 
@time    : 2022/01/22
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
import abc
import os
import threading
from typing import Union, Optional

from linktools import utils, get_logger, urlutils

logger = get_logger("frida.app")


class FridaUserScript(metaclass=abc.ABCMeta):
    __missing__ = object()

    def __init__(self):
        self._source: Union[str, object] = self.__missing__
        self._lock = threading.RLock()

    @property
    def source(self) -> Optional[str]:
        if self._source is self.__missing__:
            with self._lock:
                if self._source is self.__missing__:
                    self._source = self._load()
        return self._source

    def clear(self) -> None:
        with self._lock:
            self._source = self.__missing__

    @property
    @abc.abstractmethod
    def ident(self):
        pass

    @abc.abstractmethod
    def _load(self) -> Optional[str]:
        pass


class FridaScriptFile(FridaUserScript):

    def __init__(self, file_path: str):
        super().__init__()
        self._path = file_path

    @property
    def path(self):
        return self._path

    @property
    def ident(self):
        return self._path

    def _load(self) -> Optional[str]:
        with open(self._path, "rb") as f:
            logger.info(f"Load script: {self._path}")
            return f.read().decode("utf-8")

    def __repr__(self):
        return self.path


class FridaEvalCode(FridaUserScript):

    def __init__(self, code):
        super().__init__()
        self._code = code

    @property
    def ident(self):
        return "<anonymous>"

    def _load(self):
        return self._code


class FridaShareScript(FridaUserScript):

    def __init__(self, url: str, cached: bool = False, trusted: bool = False):
        super().__init__()
        self._url = url
        self._cached = cached
        self._trusted = trusted

    @property
    def ident(self):
        return self._url

    def _load(self):

        with urlutils.UrlFile(self._url) as file:  # 文件锁，避免多进程同时操作

            if not self._cached:
                file.clear()

            logger.info(f"Download shared script: {self._url}")
            target_path = file.save()

            with open(target_path, "rb") as f:
                source = f.read().decode("utf-8")

            if self._trusted:
                logger.info(f"Load trusted shared script: {self._url}")
                return source

            cached_md5 = ""
            cached_md5_path = target_path + ".md5"
            if os.path.exists(cached_md5_path):
                with open(cached_md5_path, "rt") as fd:
                    cached_md5 = fd.read()

            source_md5 = utils.get_md5(source)
            if cached_md5 == source_md5:
                logger.info(f"Load trusted shared script: {self._url}")
                return source

            line_count = 20
            source_lines = source.splitlines(keepends=True)
            source_summary = "".join(source_lines[:line_count])
            if len(source_lines) > line_count:
                source_summary += "... ..."

            logger.warning(
                f"This is the first time you're running this particular snippet, "
                f"or the snippet's source code has changed.{os.linesep}"
                f"Url: {self._url}{os.linesep}"
                f"Original md5: {cached_md5}{os.linesep}"
                f"Current md5: {source_md5}{os.linesep}{os.linesep}",
                f"{source_summary}",
            )
            while True:
                response = input(">>> Are you sure you'd like to trust it? [y/N]: ")
                if response.lower() in ('n', 'no') or response == '':
                    logger.info(f"Ignore untrusted shared script: {self._url}")
                    return None
                if response.lower() in ('y', 'yes'):
                    with open(cached_md5_path, "wt") as fd:
                        fd.write(source_md5)
                    logger.info(f"Load trusted shared script: {self._url}")
                    return source
