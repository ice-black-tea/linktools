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
import typing
from urllib.parse import quote

from . import utils, logger
from .decorator import locked_cached_property, cached_property


def _create_default_tools():
    tools = GeneralTools()

    # set environment variable
    index = 0
    separator = ";" if tools.system == "windows" else ":"
    dir_names = os.environ["PATH"].split(separator)
    for tool in tools:
        # dirname(executable[0]) -> environ["PATH"]
        if len(tool.executable) > 0:
            dir_name = os.path.dirname(tool.executable[0])
            if len(dir_name) > 0 and dir_name not in dir_names:
                # insert to head
                dir_names.insert(index, tool.dirname)
                index += 1
    # add all paths to environment variables
    os.environ["PATH"] = separator.join(dir_names)

    return tools


class GeneralTool(object):

    def __init__(self, system: str, name: str, config: dict):
        self._config = {
            "name": name,
            "system": system,
            "executable": None,
            "command": None,
            "download_url": None,
            "root_path": None,
            "relative_path": None,
            "absolute_path": None,
            "unpack_path": None,
        }
        self._config.update(config)

    @cached_property
    def config(self) -> dict:
        from . import resource, tools

        # fix config
        parent = self._config.get("parent")
        system = self._config.get("system")
        config = self._merge_config(self._config, parent, system)

        # download url
        url = (config.get("download_url") or "").format(**config)
        if not utils.is_empty(url):
            config["download_url"] = url

        # unpack path
        paths = [system]
        unpack_path = (config.get("unpack_path") or "").format(**config)
        if not utils.is_empty(unpack_path):
            paths.append(unpack_path)
            config["unpack_path"] = unpack_path

        # root path
        config["root_path"] = resource.get_data_dir(*paths, create=True)

        # file path
        relative_path = (config.get("relative_path") or "").format(**config)
        if not utils.is_empty(relative_path):
            config["relative_path"] = relative_path
            config["absolute_path"] = resource.get_data_path(os.path.join(config["root_path"], relative_path))

        # set executable
        command = (config.get("command") or "")
        if not utils.is_empty(command):
            command = shutil.which(command)
        if not utils.is_empty(command):
            config["absolute_path"] = command
            config["executable"] = [command]
        else:
            executable = (config.get("executable") or [config["absolute_path"]])
            if isinstance(executable, str):
                executable = [executable]
            for i in range(len(executable)):
                executable[i] = executable[i].format(tools=tools, **config)
            config["executable"] = executable

        return config

    @property
    def exists(self) -> bool:
        return os.path.exists(self.absolute_path)

    @property
    def dirname(self) -> str:
        return os.path.dirname(self.absolute_path)

    def download(self) -> None:
        from . import resource
        file = resource.get_data_path(quote(self.download_url, safe=''))
        logger.info("download: {}".format(self.download_url))
        utils.download(self.download_url, file)
        if not utils.is_empty(self.unpack_path):
            shutil.unpack_archive(file, self.root_path)
            os.remove(file)
        else:
            os.rename(file, self.absolute_path)

    def popen(self, *args: [str], **kwargs: dict) -> utils.Process:
        from . import tools
        if not os.path.exists(self.absolute_path):
            self.download()
        executable = self.executable
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

    @classmethod
    def _merge_config(cls, config: dict, parent: dict, system: str) -> dict:
        # merge config
        if parent is not None:
            fixed = cls._fix_config(parent.copy(), system)
            for key, value in config.items():
                if key not in fixed or value is not None:
                    fixed[key] = value
        else:
            fixed = config.copy()

        fixed = cls._fix_config(fixed, system)
        fixed = cls._fix_config_value(fixed, system)

        return fixed

    @classmethod
    def _fix_config(cls, config: dict, system: str) -> dict:
        obj = utils.get_item(config, system, default=None)
        if obj is not None:
            for key, value in obj.items():
                config[key] = value
        return config

    @classmethod
    def _fix_config_value(cls, config: dict, system: str) -> dict:
        for key in config.keys():
            value = utils.get_item(config[key], system, default=None)
            if value is not None:
                config[key] = value
        return config

    def __getattr__(self, item):
        return self.config[item]


class GeneralTools(object):

    def __init__(self, system: str = platform.system().lower()):
        self.system = system

    @locked_cached_property
    def items(self) -> typing.Mapping[str, GeneralTool]:
        from . import config
        configs = config.get_namespace("GENERAL_TOOL_")
        items = {}
        for key in configs:
            value = configs[key]
            if isinstance(value, dict):
                name = value.get("name") or key
                items[name] = GeneralTool(self.system, name, value)
        return items

    def __iter__(self) -> typing.Iterator[GeneralTool]:
        return iter(self.items.values())

    def __getitem__(self, item) -> typing.Union[GeneralTool, None]:
        return self.items[item] if item in self.items else None

    def __getattr__(self, item) -> typing.Union[GeneralTool, None]:
        return self.items[item] if item in self.items else None
