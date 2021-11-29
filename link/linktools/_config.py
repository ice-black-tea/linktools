#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : config.py 
@time    : 2021/08/04
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
import errno
import json
import os
import pathlib
from types import ModuleType
from typing import Optional, Union, Callable, IO, Any, Mapping, Dict

from . import version


def _create_default_config():
    config = Config()

    # 初始化路径相关参数
    config["SETTING_STORAGE_PATH"] = os.path.join(str(pathlib.Path.home()), f".{version.__name__}")
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

    # 导入环境变量LINKTOOLS_SETTING中的配置文件
    config.from_envvar("LINKTOOLS_SETTING", silent=True)

    return config


class Config(dict):

    "Code stolen from werkzeug.local.Proxy"

    def __init__(self, defaults: Optional[dict] = None):
        dict.__init__(self, defaults or {})

    def from_envvar(self, variable_name: str, silent: bool = False) -> bool:
        rv = os.environ.get(variable_name)
        if not rv:
            if silent:
                return False
            raise RuntimeError(
                f"The environment variable {variable_name!r} is not set"
                " and as such configuration could not be loaded. Set"
                " this variable and make it point to a configuration"
                " file"
            )
        return self.from_pyfile(rv, silent=silent)

    def from_pyfile(self, filename: str, silent: bool = False) -> bool:
        d = ModuleType("config")
        d.__file__ = filename
        try:
            with open(filename, mode="rb") as config_file:
                exec(compile(config_file.read(), filename, "exec"), d.__dict__)
        except OSError as e:
            if silent and e.errno in (errno.ENOENT, errno.EISDIR, errno.ENOTDIR):
                return False
            e.strerror = f"Unable to load configuration file ({e.strerror})"
            raise
        self.from_object(d)
        return True

    def from_object(self, obj: Union[object, str]) -> None:
        for key in dir(obj):
            if key.isupper():
                self[key] = getattr(obj, key)

    def from_file(self, filename: str, load: Callable[[IO[Any]], Mapping], silent: bool = False) -> bool:
        try:
            with open(filename) as f:
                obj = load(f)
        except OSError as e:
            if silent and e.errno in (errno.ENOENT, errno.EISDIR):
                return False

            e.strerror = f"Unable to load configuration file ({e.strerror})"
            raise

        return self.from_mapping(obj)

    def from_mapping(self, mapping: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> bool:
        mappings: Dict[str, Any] = {}
        if mapping is not None:
            mappings.update(mapping)
        mappings.update(kwargs)
        for key, value in mappings.items():
            if key.isupper():
                self[key] = value
        return True

    def get_namespace(self, namespace: str, lowercase: bool = True, trim_namespace: bool = True) -> Dict[str, Any]:
        rv = {}
        for k, v in self.items():
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

    def update_from_environ(self, *target_keys: [str]):
        for key in os.environ:
            if (target_keys is None or key in target_keys) and key in self:
                value = os.environ[key]
                if value is not None and len(value) > 0:
                    self[key] = value
