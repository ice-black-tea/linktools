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

from .logger import logger
from .decorator import cached_property
from .resource import resource
from .utils import utils


class ConfigTool(object):

    def __init__(self, system: str, name: str, config: dict, parent: object = None):
        self.name = name
        self.system = system
        self.parent = parent
        self.raw_config = config

    @cached_property
    def config(self) -> dict:
        # fix config
        parent = None
        if self.parent is not None:
            # noinspection PyUnresolvedReferences
            parent = self.parent.raw_config
        config = self._merge_config(self.raw_config, parent, self.system)

        # download url
        url = utils.get_item(config, "url", default="").format(**config)
        if not utils.is_empty(url):
            config["url"] = url

        # unpack path
        unpack = utils.get_item(config, "unpack", default="").format(**config)
        config["unpack"] = ""
        if not utils.is_empty(unpack):
            config["unpack"] = resource.get_cache_dir(unpack, create=True)

        # file path
        path = utils.get_item(config, "path", default="").format(**config)
        config["path"] = ""
        if not utils.is_empty(path):
            config["path"] = resource.get_cache_path(os.path.join(unpack, path))

        # set executable
        cmd = utils.get_item(config, "cmd", default="")
        if not utils.is_empty(cmd):
            cmd = shutil.which(cmd)
        if not utils.is_empty(cmd):
            config["path"] = cmd
            config["executable"] = [cmd]
        else:
            executable = utils.get_item(config, "executable", default=[config["path"]]).copy()
            for i in range(len(executable)):
                executable[i] = executable[i].format(**config)
            config["executable"] = executable

        return config

    @cached_property
    def path(self) -> str:
        if not os.path.exists(self.config["path"]):
            self.download()
        return self.config["path"]

    @cached_property
    def dirname(self) -> str:
        return os.path.dirname(self.path)

    def download(self) -> None:
        file = resource.get_cache_path(quote(self.config["url"], safe=''))
        logger.info("download: {}".format(self.config["url"]))
        utils.download(self.config["url"], file)
        if not utils.is_empty(self.config["unpack"]):
            shutil.unpack_archive(file, self.config["unpack"])
            os.remove(file)
        else:
            os.rename(file, self.config["path"])

    def popen(self, *args: [str], **kwargs: dict) -> utils.Process:
        if not os.path.exists(self.config["path"]):
            self.download()
        executable = self.config["executable"]
        if executable[0] == "python":
            args = [sys.executable, *executable[1:], *args]
            return utils.popen(*args, **kwargs)
        if executable[0] in tools.items:
            tool = tools.items[executable[0]]
            return tool.popen(*[*executable[1:], *args], **kwargs)
        if not os.access(executable[0], os.X_OK):
            os.chmod(executable[0], 0o0755)
        return utils.popen(*[*executable, *args], **kwargs)

    def exec(self, *args: [str], **kwargs: dict) -> (utils.Process, str, str):
        process = self.popen(*args, **kwargs)
        out, err = process.communicate()
        return process, out, err

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
        obj = utils.get_item(config, system, default=None)
        if obj is not None:
            for key, value in obj.items():
                config[key] = value
        return config

    @staticmethod
    def _fix_config_value(config: dict, system: str) -> dict:
        for key in config.keys():
            value = utils.get_item(config[key], system, default=None)
            if value is not None:
                config[key] = value
        return config


class ConfigTools(object):

    def __init__(self, system: str = platform.system().lower()):
        self._exclude = ["darwin", "linux", "windows"]
        self.items = {}
        self.init(system)

    @cached_property
    def config(self) -> dict:
        return resource.get_config("tools.json", "tools")

    def init(self, system: str):
        for name, config in self.config.items():
            if name not in self._exclude:
                self.items[name] = ConfigTool(system, name, config)
                for sub_name, sub_config in utils.get_item(config, "items", default={}).items():
                    if sub_name not in self._exclude:
                        self.items[sub_name] = ConfigTool(system, sub_name, sub_config, self.items[name])

    def __iter__(self):
        return iter(self.items.keys())

    def __getitem__(self, item):
        return self.items[item] if item in self.items else None

    def __getattr__(self, item):
        return self.items[item] if item in self.items else None


tools = ConfigTools()
