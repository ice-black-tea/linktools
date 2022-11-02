#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : environment.py
@time    : 2020/03/01
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
import json
import os
import pathlib

import yaml

from . import utils
from .version import __name__ as module_name


def _create_default_resource():
    from ._resource import Resource

    return Resource(
        os.path.abspath(
            os.path.join(os.path.dirname(__file__), "resource")
        )
    )


def _create_default_config():
    from ._config import Config

    config = Config()

    # 初始化全局存储路径配置，优先级低于data、temp路径
    config["SETTING_STORAGE_PATH"] = \
        os.environ.get("SETTING_STORAGE_PATH") or \
        os.path.join(str(pathlib.Path.home()), f".{module_name}")

    # 初始化data、temp路径配置
    config["SETTING_DATA_PATH"] = os.environ.get("SETTING_DATA_PATH")  # default {SETTING_STORAGE_PATH}/data
    config["SETTING_TEMP_PATH"] = os.environ.get("SETTING_TEMP_PATH")  # default {SETTING_STORAGE_PATH}/temp

    # 初始化下载相关参数
    config["SETTING_DOWNLOAD_USER_AGENT"] = \
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) " \
        "AppleWebKit/537.36 (KHTML, like Gecko) " \
        "Chrome/98.0.4758.109 " \
        "Safari/537.36"

    # 导入configs文件夹中所有配置文件
    config.from_file(resource.get_path("tools.yml"), load=yaml.safe_load)
    config.from_file(resource.get_path("android-tools.json"), load=json.load)

    # 导入环境变量LINKTOOLS_SETTING中的配置文件
    config.from_envvar("LINKTOOLS_SETTING", silent=True)

    return config


def _create_default_logger():
    from ._logger import get_logger

    return get_logger()


def _create_default_tools():
    from ._tools import GeneralTools

    tools = GeneralTools()

    # set environment variable
    index = 0
    dir_names = os.environ["PATH"].split(os.pathsep)
    for tool in tools:
        # dirname(executable[0]) -> environ["PATH"]
        if tool.executable:
            dir_name = tool.dirname
            if dir_name and dir_name not in dir_names:
                # insert to head
                dir_names.insert(index, tool.dirname)
                index += 1
    # add all paths to environment variables
    os.environ["PATH"] = os.pathsep.join(dir_names)

    return tools


resource = utils.lazy_load(_create_default_resource)
config = utils.lazy_load(_create_default_config)
logger = utils.lazy_load(_create_default_logger)
tools = utils.lazy_load(_create_default_tools)
