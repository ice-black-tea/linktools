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
from .utils import utils, _process


class _config_tools(object):

    def __init__(self, config: dict):

        self.config = config.copy()

        # download url
        url = utils.item(self.config, "url", default="").format(**self.config)
        if not utils.empty(url):
            self.config["url"] = url

        # unzip path
        unzip = utils.item(self.config, "unzip", default="").format(**self.config)
        self.config["unzip"] = resource.download_path(unzip) if not utils.empty(unzip) else ""

        # file path
        path = utils.item(self.config, "path", default="").format(**self.config)
        if not utils.empty(path):
            self.config["path"] = resource.download_path(path)

        # set executable
        cmd = utils.item(self.config, "cmd", default="")
        if not utils.empty(cmd):
            cmd = shutil.which(cmd)
        if not utils.empty(cmd):
            self.config["path"] = cmd
            self.config["executable"] = [cmd]
        else:
            executable = utils.item(self.config, "executable", default=[self.config["path"]]).copy()
            for i in range(len(executable)):
                executable[i] = executable[i].format(**self.config)
            self.config["executable"] = executable

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
        self.check_executable()
        executable = self.config["executable"]
        if executable[0] in tools.items:
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
            for sub_name, sub_config in utils.item(config, "items", default={}).items():
                sub_config = self._copy_config(config, sub_config)
                self._add_tool(sub_name, sub_config)
            config = self._copy_config(config)
            self._add_tool(name, config)

    def _add_tool(self, name, config):
        if not utils.empty(config):
            tool = _config_tools(config)
            self.items[name] = tool
            setattr(self, name, tool)

    @staticmethod
    def _copy_config(config, sub_config=None) -> dict:
        config = config.copy()
        # merge sub config
        if not utils.empty(sub_config):
            for key, value in sub_config.items():
                config[key] = value
        return config


tools = _tools()
