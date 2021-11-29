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
import subprocess
import sys
import time
import typing
from urllib.parse import quote

from . import utils, logger
from .decorator import cached_property


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


class GeneralTool(object):
    _default_config = {
        "name": "",
        "system": "",
        "cmdline": "",
        "download_url": "",
        "unpack_path": "",
        "target_path": "",
        "root_path": "",
        "absolute_path": "",
        "executable": int(time.time()),  # True or False (default: True)
        "executable_cmdline": [],
        "parent": {},
    }

    def __init__(self, container, system: str, name: str, config: dict):
        self._container = container
        self._raw_config = self._default_config.copy()
        self._raw_config.update(name=name, system=system)
        self._raw_config.update(config)

    @cached_property
    def config(self) -> dict:
        from . import resource

        # fix config
        system = self._raw_config.get("system")
        parent = self._raw_config.get("parent")
        config = self._merge_config(self._raw_config, parent, system)

        # download url
        url = (config.get("download_url") or "").format(tools=self._container, **config)
        if not utils.is_empty(url):
            config["download_url"] = url

        # unpack path
        paths = ["tools"]
        unpack_path = (config.get("unpack_path") or "").format(tools=self._container, **config)
        if not utils.is_empty(unpack_path):
            paths.append(unpack_path)
            config["unpack_path"] = unpack_path

        # root path: {system}/{unpack_path}/
        config["root_path"] = resource.get_data_dir(*paths, create=True)

        # file path: {system}/{unpack_path}/{target_path}
        target_path = (config.get("target_path") or "").format(tools=self._container, **config)
        if not utils.is_empty(target_path):
            config["target_path"] = target_path
            config["absolute_path"] = os.path.join(config["root_path"], target_path)

        # is it executable
        config["executable"] = True if config.get("executable") else False

        # set executable cmdline
        cmdline = (config.get("cmdline") or "")
        if not utils.is_empty(cmdline):
            cmdline = shutil.which(cmdline)
        if not utils.is_empty(cmdline):
            config["absolute_path"] = cmdline
            config["executable_cmdline"] = [cmdline]
        else:
            executable_cmdline = (config.get("executable_cmdline") or [config["absolute_path"]])
            if isinstance(executable_cmdline, str):
                executable_cmdline = [executable_cmdline]
            for i in range(len(executable_cmdline)):
                executable_cmdline[i] = executable_cmdline[i].format(tools=self._container, **config)
            config["executable_cmdline"] = executable_cmdline

        return config

    @property
    def exists(self) -> bool:
        return os.path.exists(self.absolute_path)

    @property
    def dirname(self) -> str:
        return os.path.dirname(self.absolute_path)

    def prepare(self, force_download=False) -> None:
        # remove tool files first
        if force_download:
            self.clear()

        # download tool files
        if not self.exists:
            from . import resource
            file = resource.get_temp_path(quote(self.download_url, safe=''))
            logger.debug("download: {}".format(self.download_url))
            utils.download(self.download_url, file)
            if not utils.is_empty(self.unpack_path):
                shutil.unpack_archive(file, self.root_path)
                os.remove(file)
            else:
                os.rename(file, self.absolute_path)

        # change tool file mode
        if self.executable and not os.access(self.absolute_path, os.X_OK):
            logger.debug(f"chmod 755 {self.absolute_path}")
            os.chmod(self.absolute_path, 0o0755)

    def clear(self) -> None:
        if self.exists:
            if not utils.is_empty(self.unpack_path):
                shutil.rmtree(self.root_path, ignore_errors=True)
            elif self.absolute_path.startswith(self.root_path):
                os.remove(self.absolute_path)

    def popen(self, *args: [str], **kwargs: dict) -> subprocess.Popen:
        self.prepare(force_download=False)
        executable_cmdline = self.executable_cmdline
        if executable_cmdline[0] == "python":
            args = [sys.executable, *executable_cmdline[1:], *args]
            return utils.popen(*args, **kwargs)
        if executable_cmdline[0] in self._container.items:
            tool = self._container.items[executable_cmdline[0]]
            return tool.popen(*[*executable_cmdline[1:], *args], **kwargs)
        return utils.popen(*[*executable_cmdline, *args], **kwargs)

    def exec(self, *args: [str], **kwargs: dict) -> (subprocess.Popen, str, str):
        process = self.popen(*args, **kwargs)
        out, err = process.communicate()
        return process, out, err

    @classmethod
    def _merge_config(cls, config: dict, parent: dict, system: str) -> dict:
        # merge config
        if parent is not None and len(parent) > 0:
            fixed = cls._fix_config_key(parent.copy(), system)
            fixed = cls._fix_config_value(fixed, system)
            for key, value in fixed.items():
                if key not in config or config[key] == cls._default_config[key]:
                    config[key] = value

        config = cls._fix_config_key(config, system)
        config = cls._fix_config_value(config, system)

        return config

    @classmethod
    def _fix_config_key(cls, config: dict, system: str) -> dict:
        if system in config:
            obj = config.pop(system)
            if isinstance(obj, dict):
                for key, value in obj.items():
                    config[key] = value
        return config

    @classmethod
    def _fix_config_value(cls, config: dict, system: str) -> dict:
        for key in config.keys():
            obj = config[key]
            if isinstance(obj, dict):
                if system in obj:
                    config[key] = obj.get(system)
        return config

    def __getattr__(self, item):
        return self.config[item]


class GeneralTools(object):

    def __init__(self, system: str = platform.system().lower()):
        self.items = self._init_items(system)

    def _init_items(self, system) -> typing.Mapping[str, GeneralTool]:
        from . import config
        configs = config.get_namespace("GENERAL_TOOL_")
        items = {}
        for key in configs:
            value = configs[key]
            if isinstance(value, dict):
                name = value.get("name") or key
                items[name] = GeneralTool(self, system, name, value)
        return items

    def __iter__(self) -> typing.Iterator[GeneralTool]:
        return iter(self.items.values())

    def __getitem__(self, item) -> typing.Union[GeneralTool, None]:
        return self.items[item] if item in self.items else None

    def __getattr__(self, item) -> typing.Union[GeneralTool, None]:
        return self.items[item] if item in self.items else None
