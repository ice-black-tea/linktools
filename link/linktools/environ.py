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
import platform

import colorama
import yaml

from . import utils
from ._config import Config
from ._logger import Logger, get_logger
from ._resource import Resource
from ._tools import GeneralTools
from .version import __name__ as module_name


def _create_default_tools():
    tools = GeneralTools()

    # set environment variable
    index = 0
    dir_names = os.environ["PATH"].split(os.pathsep)
    for tool in tools:
        # dirname(executable[0]) -> environ["PATH"]
        if tool.executable:
            dir_name = tool.dirname
            if len(dir_name) > 0 and dir_name not in dir_names:
                # insert to head
                dir_names.insert(index, tool.dirname)
                index += 1
    # add all paths to environment variables
    os.environ["PATH"] = os.pathsep.join(dir_names)

    return tools


def _create_default_config():
    config = Config()

    # 初始化路径相关参数
    config["SETTING_STORAGE_PATH"] = os.path.join(str(pathlib.Path.home()), f".{module_name}")
    config["SETTING_DATA_PATH"] = None  # default {SETTING_STORAGE_PATH}/data
    config["SETTING_TEMP_PATH"] = None  # default {SETTING_STORAGE_PATH}/temp

    # 初始化下载相关参数
    config["SETTING_DOWNLOAD_USER_AGENT"] = \
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) " \
        "AppleWebKit/537.36 (KHTML, like Gecko) " \
        "Chrome/75.0.3770.100 " \
        "Safari/537.36"

    # 导入configs文件夹中所有配置文件
    config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "configs"))
    for name in os.listdir(config_path):
        path = os.path.join(config_path, name)
        if os.path.isdir(path):
            continue
        elif path.endswith(".py"):
            config.from_pyfile(path)
        elif path.endswith(".json"):
            config.from_file(path, load=json.load)
        elif path.endswith(".yml"):
            config.from_file(path, load=yaml.safe_load)

    # 导入环境变量LINKTOOLS_SETTING中的配置文件
    config.from_envvar("LINKTOOLS_SETTING", silent=True)

    return config


def _create_default_logger():
    if "windows" in platform.system().lower():  # works for Win7, 8, 10 ...
        import ctypes
        k = ctypes.windll.kernel32
        k.SetConsoleMode(k.GetStdHandle(-11), 7)
    colorama.init(autoreset=False)
    return get_logger(module_name)


resource: Resource = Resource()
config: Config = utils.lazy_load(_create_default_config)
logger: Logger = utils.lazy_load(_create_default_logger)
tools: GeneralTools = utils.lazy_load(_create_default_tools)
