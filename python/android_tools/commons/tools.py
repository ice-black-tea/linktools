#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : tools.py 
@time    : 2018/12/11
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
import os
import platform
import shutil
from urllib.parse import quote

from .resource import resource
from .utils import utils, _process


class _config_tools(object):
    _system = platform.system().lower()

    def __init__(self, keyword: str, cmd: str = None):
        self.config = resource.get_config(keyword)
        # support darwin, linux, windows
        if utils.contain(self.config, _config_tools._system):
            self.config = utils.item(self.config, _config_tools._system)

        # 1.url [default ""]
        self.url = utils.item(self.config, "url", default="").format(**self.config)

        # 2.unzip [default False]
        self.unzip = utils.item(self.config, "unzip", default=False)

        # 3.path [default ""]
        path = utils.item(self.config, "path", default="").format(**self.config)
        self.path = resource.download_path(path)

        # 4.executable [default ""]
        self.executable = None
        if not utils.empty(cmd):
            self.executable = shutil.which(cmd)
        if utils.empty(self.executable):
            executable = utils.item(self.config, "executable", default="").format(**self.config)
            self.executable = resource.download_path(executable)

    def check_executable(self):
        if not os.path.exists(self.executable):
            tmp_file = resource.download_path(quote(self.url, safe=''))
            utils.download(self.url, tmp_file)
            if not self.unzip:
                os.rename(tmp_file, self.executable)
            else:
                shutil.unpack_archive(tmp_file, self.path)
                os.remove(tmp_file)
            os.chmod(self.executable, 0o0755)

    def exec(self, *args: [str], **kwargs):
        pass


class _adb(_config_tools):

    def __init__(self):
        super().__init__("adb", cmd="adb")

    def exec(self, *args: [str], **kwargs) -> _process:
        self.check_executable()
        args = [self.executable, *args]
        return utils.exec(*args, **kwargs)


class _java(_config_tools):

    def __init__(self):
        super().__init__("java", cmd="java")

    def exec(self, *args: [str], **kwargs) -> _process:
        self.check_executable()
        args = [self.executable, *args]
        return utils.exec(*args, **kwargs)


class _apktool(_config_tools):

    def __init__(self):
        super().__init__("apktool")

    def exec(self, *args: [str], **kwargs) -> _process:
        self.check_executable()
        args = ["-jar", self.executable, *args]
        return tools.java.exec(*args, **kwargs)


class _smali(_config_tools):

    def __init__(self):
        super().__init__("smali")

    def exec(self, *args: [str], **kwargs) -> _process:
        self.check_executable()
        args = ["-jar", self.executable, *args]
        return tools.java.exec(*args, **kwargs)


class _baksmali(_config_tools):

    def __init__(self):
        super().__init__("baksmali")

    def exec(self, *args: [str], **kwargs) -> _process:
        self.check_executable()
        args = ["-jar", self.executable, *args]
        return tools.java.exec(*args, **kwargs)


class tools(object):

    adb = _adb()
    java = _java()
    apktool = _apktool()
    smali = _smali()
    baksmali = _baksmali()

    _items = None

    @staticmethod
    def items() -> dict:
        if utils.empty(tools._items):
            items = {}
            attrs = vars(tools)
            for key in attrs.keys():
                if isinstance(attrs[key], _config_tools):
                    items[key] = attrs[key]
            tools._items = items
        return tools._items
