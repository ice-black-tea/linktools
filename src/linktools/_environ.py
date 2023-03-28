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
import abc
import json
import os
import pathlib
from typing import TypeVar, Type, Optional, Any, Dict

import yaml

from .decorator import cached_property
from .version import \
    __name__ as __module_name__, \
    __description__ as __module_description__, \
    __version__ as __module_version__

T = TypeVar("T")
root_path = os.path.dirname(__file__)
asset_path = os.path.join(root_path, "assets")


class BaseEnviron(abc.ABC):
    __missing__ = object()

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """
        模块名
        """
        pass

    @property
    @abc.abstractmethod
    def version(self) -> str:
        """
        模块版本号
        """
        pass

    @property
    def description(self) -> str:
        """
        模块描述
        """
        return ""

    @property
    @abc.abstractmethod
    def root_path(self) -> str:
        """
        模块根目录
        """
        pass

    @cached_property
    def data_path(self):
        """
        存放文件目录
        """
        path = self.get_config("DATA_PATH")
        if not path:
            path = os.path.join(self.get_config("STORAGE_PATH"), "data")
        return path

    @cached_property
    def temp_path(self):
        """
        存放临时文件目录
        """
        path = self.get_config("TEMP_PATH")
        if not path:
            path = os.path.join(self.get_config("STORAGE_PATH"), "temp")
        return path

    @classmethod
    def _get_path(cls, root_path: str, *paths: [str], create: bool = False, create_parent: bool = False):
        target_path = parent_path = os.path.abspath(root_path)
        for path in paths:
            target_path = os.path.abspath(os.path.join(parent_path, path))
            common_path = os.path.commonpath([parent_path, target_path])
            if target_path == parent_path or parent_path != common_path:
                raise Exception(f"Unsafe path \"{path}\"")
            parent_path = target_path
        dir_path = None
        if create:
            dir_path = target_path
        elif create_parent:
            dir_path = os.path.dirname(target_path)
        if dir_path is not None:
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
        return target_path

    def get_path(self, *paths: str):
        """
        获取根目录下的子目录
        """
        return self._get_path(self.root_path, *paths, create=False, create_parent=False)

    def get_data_path(self, *paths: str, create_parent: bool = False):
        """
        获取数据目录下的子路径
        """
        return self._get_path(self.data_path, *paths, create=False, create_parent=create_parent)

    def get_data_dir(self, *paths: str, create: bool = False):
        """
        获取数据目录下的子目录
        """
        return self._get_path(self.data_path, *paths, create=create, create_parent=False)

    def get_temp_path(self, *paths: str, create_parent: bool = False):
        """
        获取临时文件目录下的子路径
        """
        return self._get_path(self.temp_path, *paths, create=False, create_parent=create_parent)

    def get_temp_dir(self, *paths: str, create: bool = False):
        """
        获取临时文件目录下的子目录
        """
        return self._get_path(self.temp_path, *paths, create=create, create_parent=False)

    @cached_property
    def logger(self):
        """
        模块根logger
        """
        from ._logging import get_logger

        return get_logger(prefix=self.name)

    def get_logger(self, name: str = None):
        """
        获取模块名作为前缀的logger
        """
        from ._logging import get_logger

        return get_logger(name=name, prefix=self.name)

    @cached_property
    def _config(self):
        from ._config import Config

        config = Config()

        # 初始化全局存储路径配置，优先级低于data、temp路径
        config["STORAGE_PATH"] = \
            os.environ.get("STORAGE_PATH") or \
            os.path.join(str(pathlib.Path.home()), f".{__module_name__}")

        # 初始化下载相关参数
        config["SETTING_DOWNLOAD_USER_AGENT"] = \
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) " \
            "AppleWebKit/537.36 (KHTML, like Gecko) " \
            "Chrome/98.0.4758.109 " \
            "Safari/537.36"

        # 导入configs文件夹中所有配置文件
        config.from_file(self._get_path(asset_path, "tools.yml"), load=yaml.safe_load)
        config.from_file(self._get_path(asset_path, "android-tools.json"), load=json.load)

        # 导入环境变量LINKTOOLS_SETTING中的配置文件
        config.from_envvar("LINKTOOLS_SETTING", silent=True)

        return config

    def get_configs(self, namespace: str, lowercase: bool = True, trim_namespace: bool = True) -> Dict[str, Any]:
        """
        根据命名空间获取配置列表
        """
        rv = {}
        for k, v in self._config.items():
            if not k.startswith(namespace):
                continue
            if trim_namespace:
                key = k[len(namespace):]
            else:
                key = k
            if lowercase:
                key = key.lower()
            rv[key] = v
        return rv

    def get_config(self, key, cast_type: Type[T] = None, accept_empty: bool = False, default: T = None) -> Optional[T]:
        """
        获取指定配置，优先会从环境变量中获取
        """
        try:
            new_key = f"{self.name}_{key}".upper()
            if new_key in os.environ:
                value = os.environ.get(new_key)
                if accept_empty or value:
                    return value if cast_type is None else cast_type(value)
        except Exception as e:
            self.logger.debug(f"Get config \"{key}\" from system environ error: {e}")

        try:
            if key in self._config:
                value = self._config.get(key)
                if accept_empty or value:
                    return value if cast_type is None else cast_type(value)
        except Exception as e:
            self.logger.debug(f"Get config \"{key}\" error: {e}")

        return default

    def update_configs(self, **kwargs) -> None:
        """
        更新配置
        """
        self._config.update(**kwargs)

    def set_config(self, key: str, value: Any) -> None:
        """
        更新配置
        """
        self._config[key] = value

    @cached_property
    def tools(self):
        """
        工具集
        """
        from ._tools import ToolContainer

        tools = ToolContainer()

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

    def get_tool(self, name: str, **kwargs):
        """
        获取指定工具
        """
        tool = self.tools[name]
        if len(kwargs) != 0:
            tool = tool.copy(**kwargs)
        return tool

    @property
    def debug(self) -> bool:
        """
        debug模式
        """
        from . import utils

        return self.get_config("DEBUG", cast_type=utils.bool, default=False)

    @debug.setter
    def debug(self, value: bool):
        """
        debug模式
        """
        self.set_config("DEBUG", value)

    @property
    def show_log_time(self) -> bool:
        """
        显示日志时间
        """
        from . import utils

        return self.get_config("SHOW_LOG_TIME", cast_type=utils.bool, default=False)

    @show_log_time.setter
    def show_log_time(self, value: bool):
        """
        显示日志时间
        """
        from ._logging import LogHandler
        handler = LogHandler.get_instance()
        if handler:
            handler.show_time = value
        self.set_config("SHOW_LOG_TIME", value)

    @property
    def show_log_level(self) -> bool:
        """
        显示日志级别
        """
        from . import utils

        return self.get_config("SHOW_LOG_LEVEL", cast_type=utils.bool, default=True)

    @show_log_level.setter
    def show_log_level(self, value: bool):
        """
        显示日志级别
        """
        from ._logging import LogHandler
        handler = LogHandler.get_instance()
        if handler:
            handler.show_level = value
        self.set_config("SHOW_LOG_LEVEL", value)

    @property
    def system(self) -> str:
        """
        系统名称
        """
        return self.tools.system


class Environ(BaseEnviron):

    @property
    def name(self) -> str:
        return __module_name__

    @property
    def description(self) -> str:
        return __module_description__

    @property
    def version(self) -> str:
        return __module_version__

    @property
    def root_path(self) -> str:
        return root_path

    def get_asset_path(self, *paths: str):
        return self._get_path(asset_path, *paths)


environ = Environ()
