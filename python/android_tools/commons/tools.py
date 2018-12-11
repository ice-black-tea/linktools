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
from .utils import utils


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


class apktool(object):

    _t = _config_tools("apktool")

    @staticmethod
    def exec(*args: [str], **kwargs):
        apktool._t.check_executable()
        args = ["java", "-jar", apktool._t.executable, *args]
        return utils.exec(*args, **kwargs)


class smali(object):

    _t = _config_tools("smali")

    @staticmethod
    def exec(*args: [str], **kwargs):
        smali._t.check_executable()
        args = ["java", "-jar", smali._t.executable, *args]
        return utils.exec(*args, **kwargs)


class baksmali(object):

    _t = _config_tools("baksmali")

    @staticmethod
    def exec(*args: [str], **kwargs):
        baksmali._t.check_executable()
        args = ["java", "-jar", baksmali._t.executable, *args]
        return utils.exec(*args, **kwargs)
