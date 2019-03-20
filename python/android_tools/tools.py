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
import sys
from urllib.parse import quote

from .decorator import singleton
from .resource import resource
from .utils import Utils, _Process


class ConfigTool(object):

    def __init__(self, system: str, name: str, config: dict, parent: object = None):
        self.name = name
        self.system = system
        self.config = None
        self.parent = parent
        self.origin_config = config

    def init_config(self) -> None:
        if self.config is not None:
            return

        # fix config
        parent = None
        if self.parent is not None:
            # noinspection PyUnresolvedReferences
            parent = self.parent.origin_config
        config = self._merge_config(self.origin_config, parent, self.system)

        # download url
        url = Utils.get_item(config, "url", default="").format(**config)
        if not Utils.is_empty(url):
            config["url"] = url

        # unpack path
        unpack = Utils.get_item(config, "unpack", default="").format(**config)
        config["unpack"] = ""
        if not Utils.is_empty(unpack):
            config["unpack"] = resource.get_store_path(unpack, create_dir=True)

        # file path
        path = Utils.get_item(config, "path", default="").format(**config)
        if not Utils.is_empty(path):
            config["path"] = resource.get_store_path(path)

        # set executable
        cmd = Utils.get_item(config, "cmd", default="")
        if not Utils.is_empty(cmd):
            cmd = shutil.which(cmd)
        if not Utils.is_empty(cmd):
            config["path"] = cmd
            config["executable"] = [cmd]
        else:
            executable = Utils.get_item(config, "executable", default=[config["path"]]).copy()
            for i in range(len(executable)):
                executable[i] = executable[i].format(**config)
            config["executable"] = executable

        self.config = config

    def download(self, force: bool = False) -> None:
        self.init_config()
        if not os.path.exists(self.config["path"]) or force:
            file = resource.get_store_path(quote(self.config["url"], safe=''))
            Utils.download(self.config["url"], file)
            if not Utils.is_empty(self.config["unpack"]):
                shutil.unpack_archive(file, self.config["unpack"])
                os.remove(file)
            else:
                os.rename(file, self.config["path"])

    def exec(self, *args: [str], **kwargs) -> _Process:
        self.download(force=False)
        executable = self.config["executable"]
        if executable[0] == "python":
            args = [sys.executable, *executable[1:], *args]
            return Utils.exec(*args, **kwargs)
        if executable[0] in tools.items:
            tool = tools.items[executable[0]]
            return tool.exec(*[*executable[1:], *args], **kwargs)
        if not os.access(executable[0], os.X_OK):
            os.chmod(executable[0], 0o0755)
        return Utils.exec(*[*executable, *args], **kwargs)

    @staticmethod
    def _merge_config(config: dict, parent: dict, system: str) -> dict:
        # merge config
        if parent is not None:
            # noinspection PyProtectedMember,PyUnresolvedReferences
            fixed = ConfigTool._fix_config(parent.copy(), system)
            for key, value in config.items():
                fixed[key] = value
        else:
            fixed = config.copy()

        fixed = ConfigTool._fix_config(fixed, system)
        fixed = ConfigTool._fix_config_value(fixed, system)
        fixed["system"] = system

        return fixed

    @staticmethod
    def _fix_config(config: dict, system: str) -> dict:
        obj = Utils.get_item(config, system, default=None)
        if obj is not None:
            for key, value in obj.items():
                config[key] = value
        return config

    @staticmethod
    def _fix_config_value(config: dict, system: str) -> dict:
        for key in config.keys():
            value = Utils.get_item(config[key], system, default=None)
            if value is not None:
                config[key] = value
        return config


@singleton
class ConfigTools(object):

    @staticmethod
    def _get_config() -> dict:
        if not hasattr(ConfigTools, "_config"):
            setattr(ConfigTools, "_config", resource.get_config("tools.json", "tools"))
        return getattr(ConfigTools, "_config")

    def __init__(self):
        self._exclude = ["darwin", "linux", "windows"]
        self.items = {}
        self.init()

    def init(self, system: str = platform.system().lower()):
        for name, config in self._get_config().items():
            if name in self._exclude:
                continue
            tool = ConfigTool(system, name, config)
            self._append(name, tool)
            for sub_name, sub_config in Utils.get_item(config, "items", default={}).items():
                if sub_name in self._exclude:
                    continue
                sub_tool = ConfigTool(system, sub_name, sub_config, tool)
                self._append(sub_name, sub_tool)

    def _append(self, name, tool):
        self.items[name] = tool
        setattr(self, name, tool)

    def __iter__(self):
        return iter(self.items.values())

    def __getitem__(self, item):
        return Utils.get_item(self.items, item, default=None)


tools = ConfigTools()
