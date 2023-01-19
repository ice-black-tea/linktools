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
import json
import os
import threading
from typing import Union, Optional

from rich import get_console
from rich.prompt import Confirm
from rich.table import Table

from .. import utils, get_logger

_logger = get_logger("frida.app")


class FridaUserScript(metaclass=abc.ABCMeta):
    __missing__ = object()

    def __init__(self):
        self._source: Union[str, object] = self.__missing__
        self._lock = threading.RLock()

    @property
    def source(self) -> Optional[str]:
        return self.load()

    def load(self) -> Optional[str]:
        with self._lock:
            if self._source is self.__missing__:
                self._source = self._load()
            return self._source

    def clear(self) -> None:
        with self._lock:
            self._source = self.__missing__

    @property
    @abc.abstractmethod
    def filename(self):
        pass

    @abc.abstractmethod
    def _load(self) -> Optional[str]:
        pass

    def to_dict(self) -> dict:
        return {"filename": self.filename, "source": self.source}

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    def __repr__(self):
        class_name = self.__class__.__name__
        if class_name.startswith("Frida"):
            class_name = class_name[len("Frida"):]
        return f"{class_name}(filename={self.filename})"


class FridaScriptFile(FridaUserScript):

    def __init__(self, file_path: str):
        super().__init__()
        self._path = file_path

    @property
    def path(self):
        return self._path

    @property
    def filename(self):
        return self._path

    def _load(self) -> Optional[str]:
        with open(self._path, "rb") as f:
            _logger.info(f"Load {self}")
            return f.read().decode("utf-8")


class FridaEvalCode(FridaUserScript):

    def __init__(self, code):
        super().__init__()
        self._code = code

    @property
    def filename(self):
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
    def filename(self):
        return self._url

    def _load(self):

        with utils.UrlFile(self._url) as file:  # 文件锁，避免多进程同时操作

            if not self._cached:
                file.clear()

            _logger.info(f"Download {self}")
            target_path = file.save()

            with open(target_path, "rb") as f:
                source = f.read().decode("utf-8")

            if self._trusted:
                _logger.info(f"Load trusted {self}")
                return source

            cached_md5 = ""
            cached_md5_path = target_path + ".md5"
            if os.path.exists(cached_md5_path):
                with open(cached_md5_path, "rt") as fd:
                    cached_md5 = fd.read()

            source_md5 = utils.get_md5(source)
            if cached_md5 == source_md5:
                _logger.info(f"Load trusted {self}")
                return source

            line_count = 20
            source_lines = source.splitlines(keepends=True)
            source_summary = "".join(source_lines[:line_count])
            if len(source_lines) > line_count:
                source_summary += "... ..."

            table = Table(show_lines=True)
            table.add_column("Property", justify="right", style="cyan", no_wrap=True)
            table.add_column("Content", style="magenta")
            table.add_row("Url", self._url)
            table.add_row("Original md5", cached_md5)
            table.add_row("Current md5", source_md5)
            table.add_row("Source", source_summary)

            console = get_console()
            console.print(table)

            prompt = f"This is the first time you're running this particular snippet, " \
                     f"or the snippet's source code has changed. {os.linesep}" \
                     f"Are you sure you'd like to trust it?"
            if Confirm.ask(prompt, console=console):
                with open(cached_md5_path, "wt") as fd:
                    fd.write(source_md5)
                _logger.info(f"Load trusted {self}")
                return source
            else:
                _logger.info(f"Ignore untrusted {self}")
                return None
