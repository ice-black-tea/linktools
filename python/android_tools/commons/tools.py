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

from .resource import resource
from .utils import utils, _process


class config_tool(object):

    def __init__(self, name: str, config: dict, parent: object = None):
        self.name = name
        self.config = None
        self.parent = parent
        self._config = config

    def init_config(self) -> None:
        if self.config is not None:
            return

        # merge config
        if self.parent is not None:
            # noinspection PyProtectedMember,PyUnresolvedReferences
            config = self.parent._config.copy()
            for key, value in self._config.items():
                config[key] = value
        else:
            config = self._config.copy()

        # download url
        url = utils.item(config, "url", default="").format(**config)
        if not utils.empty(url):
            config["url"] = url

        # unpack path
        unpack = utils.item(config, "unpack", default="").format(**config)
        config["unpack"] = resource.download_path(unpack) if not utils.empty(unpack) else ""

        # file path
        path = utils.item(config, "path", default="").format(**config)
        if not utils.empty(path):
            config["path"] = resource.download_path(path)

        # set executable
        cmd = utils.item(config, "cmd", default="")
        if not utils.empty(cmd):
            cmd = shutil.which(cmd)
        if not utils.empty(cmd):
            config["path"] = cmd
            config["executable"] = [cmd]
        else:
            executable = utils.item(config, "executable", default=[config["path"]]).copy()
            for i in range(len(executable)):
                executable[i] = executable[i].format(**config)
            config["executable"] = executable

        self.config = config

    def download(self, force: bool = False) -> None:
        self.init_config()
        if not os.path.exists(self.config["path"]) or force:
            file = resource.download_path(quote(self.config["url"], safe=''))
            utils.download(self.config["url"], file)
            if not utils.empty(self.config["unpack"]):
                shutil.unpack_archive(file, self.config["unpack"])
                os.remove(file)
            else:
                os.rename(file, self.config["path"])

    def exec(self, *args: [str], **kwargs) -> _process:
        self.download(force=False)
        executable = self.config["executable"]
        if executable[0] == "python":
            args = [sys.executable, *executable[1:], *args]
            return utils.exec(*args, **kwargs)
        if executable[0] in tools._items:
            tool = tools._items[executable[0]]
            return tool.exec(*[*executable[1:], *args], **kwargs)
        if not os.access(executable[0], os.X_OK):
            os.chmod(executable[0], 0o0755)
        return utils.exec(*[*executable, *args], **kwargs)


class config_tools():

    def __init__(self, system: str = platform.system().lower()):
        self._items = {}
        for name, config in resource.get_config("tools").items():
            # darwin, linux or windows
            config = utils.item(config, system, default=config)
            if utils.empty(config):
                continue
            tool = config_tool(name, config)
            self._append(name, tool)
            for sub_name, sub_config in utils.item(config, "items", default={}).items():
                sub_tool = config_tool(sub_name, sub_config, tool)
                self._append(sub_name, sub_tool)

    def _append(self, name, tool):
        self._items[name] = tool
        setattr(self, name, tool)

    def __iter__(self):
        return iter(self._items.values())

    def __getitem__(self, item):
        return utils.item(self._items, item, default=None)


tools = config_tools()
