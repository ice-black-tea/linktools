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


class _config_tools(object):

    def __init__(self, config: dict, parent: object = None):
        self._config = config
        self.config = None
        self.parent = parent

    def init_config(self) -> None:
        if self.config is not None:
            return

        # merge config
        if self.parent is not None:
            # noinspection PyProtectedMember,PyUnresolvedReferences
            config = self.parent._config.copy()
            if not utils.empty(self.parent):
                for key, value in self._config.items():
                    config[key] = value
        else:
            config = self._config.copy()

        # download url
        url = utils.item(config, "url", default="").format(**config)
        if not utils.empty(url):
            config["url"] = url

        # unzip path
        unzip = utils.item(config, "unzip", default="").format(**config)
        config["unzip"] = resource.download_path(unzip) if not utils.empty(unzip) else ""

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

    def check_executable(self) -> None:
        if not os.path.exists(self.config["path"]):
            print(self.config["url"])
            file = resource.download_path(quote(self.config["url"], safe=''))
            utils.download(self.config["url"], file)
            if not utils.empty(self.config["unzip"]):
                shutil.unpack_archive(file, self.config["unzip"])
                os.remove(file)
            else:
                os.rename(file, self.config["path"])
            os.chmod(self.config["path"], 0o0755)
        elif not os.access(self.config["path"], os.X_OK):
            os.chmod(self.config["path"], 0o0755)

    def exec(self, *args: [str], **kwargs) -> _process:
        self.init_config()
        self.check_executable()
        executable = self.config["executable"]
        if executable[0] == "python":
            args = [sys.executable, *executable[1:], *args]
            return utils.exec(*args, **kwargs)
        elif executable[0] in tools.items:
            tool = tools.items[executable[0]]
            return tool.exec(*[*executable[1:], *args], **kwargs)
        return utils.exec(*[*executable, *args], **kwargs)


class _tools:

    _system = platform.system().lower()

    def __init__(self):
        self.items = {}
        for name, config in resource.get_config("tools").items():
            # darwin, linux or windows
            config = utils.item(config, _tools._system, default=config)
            if utils.empty(config):
                continue
            tool = _config_tools(config)
            self._add_tool(name, tool)
            for sub_name, sub_config in utils.item(config, "items", default={}).items():
                sub_tool = _config_tools(sub_config, tool)
                self._add_tool(sub_name, sub_tool)

    def _add_tool(self, name, tool):
        self.items[name] = tool
        setattr(self, name, tool)


tools = _tools()
