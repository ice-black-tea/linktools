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

from .utils import utils
from .resource import resource


class apktool(object):

    config = resource.get_config("apktool")
    version = config["version"]
    executable = resource.download_path(config["name"].format(version=version))

    @staticmethod
    def exec(*args: [str], **kwargs):
        if not os.path.exists(apktool.executable):
            utils.download(apktool.config["url"].format(version=apktool.version), apktool.executable)
        args = ["java", "-jar", apktool.executable, *args]
        return utils.exec(*args, **kwargs)


class smali(object):

    config = resource.get_config("smali")
    version = config["version"]
    executable = resource.download_path(config["name"].format(version=version))

    @staticmethod
    def exec(*args: [str], **kwargs):
        if not os.path.exists(smali.executable):
            utils.download(smali.config["url"].format(version=smali.version), smali.executable)
        args = ["java", "-jar", smali.executable, *args]
        return utils.exec(*args, **kwargs)


class baksmali(object):

    config = resource.get_config("baksmali")
    version = config["version"]
    executable = resource.download_path(config["name"].format(version=version))

    @staticmethod
    def exec(*args: [str], **kwargs):
        if not os.path.exists(baksmali.executable):
            utils.download(baksmali.config["url"].format(version=baksmali.version), baksmali.executable)
        args = ["java", "-jar", baksmali.executable, *args]
        return utils.exec(*args, **kwargs)