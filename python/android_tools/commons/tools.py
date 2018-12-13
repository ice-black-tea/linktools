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

    def __init__(self):
        self.config = resource.get_config(self.__class__.__name__)

        # darwin, linux or windows
        if utils.contain(self.config, _config_tools._system):
            self.config = utils.item(self.config, _config_tools._system)

        # 1.url [default ""]
        self.url = utils.item(self.config, "url", default="").format(**self.config)

        # 2.unzip [default ""]
        self.unzip = utils.item(self.config, "unzip", default="").format(**self.config)
        if not utils.empty(self.unzip):
            self.unzip = resource.download_path(self.unzip)

        # 3.executable [default ""]
        executable = None
        cmd = utils.item(self.config, "cmd", default="")
        if not utils.empty(cmd):
            executable = shutil.which(cmd)
        if utils.empty(executable):
            executable = utils.item(self.config, "executable", default="").format(**self.config)
            executable = resource.download_path(executable)
        self.executable = executable

    def check_executable(self):
        if not os.path.exists(self.executable):
            file = resource.download_path(quote(self.url, safe=''))
            utils.download(self.url, file)
            if not utils.empty(self.unzip):
                shutil.unpack_archive(file, self.unzip)
                os.remove(file)
            else:
                os.rename(file, self.executable)
            os.chmod(self.executable, 0o0755)

    def exec(self, *args: [str], **kwargs):
        raise Exception("not yet implemented")


class _tools:
    class adb(_config_tools):

        def exec(self, *args: [str], **kwargs) -> _process:
            self.check_executable()
            args = [self.executable, *args]
            return utils.exec(*args, **kwargs)

    class java(_config_tools):

        def exec(self, *args: [str], **kwargs) -> _process:
            self.check_executable()
            args = [self.executable, *args]
            return utils.exec(*args, **kwargs)

    class apktool(_config_tools):

        def exec(self, *args: [str], **kwargs) -> _process:
            self.check_executable()
            args = ["-jar", self.executable, *args]
            return tools.java.exec(*args, **kwargs)

    class smali(_config_tools):

        def exec(self, *args: [str], **kwargs) -> _process:
            self.check_executable()
            args = ["-jar", self.executable, *args]
            return tools.java.exec(*args, **kwargs)

    class baksmali(_config_tools):

        def exec(self, *args: [str], **kwargs) -> _process:
            self.check_executable()
            args = ["-jar", self.executable, *args]
            return tools.java.exec(*args, **kwargs)

    def __init__(self):
        self.items = {}
        for key, value in _tools.__dict__.items():
            if not key.startswith("__"):
                self.items[key] = value()
                setattr(self, key, self.items[key])


tools = _tools()
