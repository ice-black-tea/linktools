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

__all__ = ("GeneralTool", "GeneralTools")

import os
import platform
import shutil
import subprocess
import sys
import warnings
from typing import Dict, Union, Mapping, Iterator

from . import utils, urlutils
from ._environ import resource, config
from ._logger import get_logger
from .decorator import cached_property

logger = get_logger("utils")


class Parser(object):

    def __init__(self, *items):
        self._verifies = tuple(self._get_verify(item) for item in items)

    def parse(self, cfg: Dict):
        result = {}
        for key in cfg:
            result[key] = self._extend_field(cfg, key)
        return result

    def _extend_field(self, cfg, key: str, default=None):
        value = utils.get_item(cfg, key, default=default)
        if isinstance(value, dict) and "case" in value:
            case_block = value.get("case")  # ==> find "case"
            # traverse all blocks
            for cond_block in case_block:
                # if it is a when block
                when_block = utils.get_item(cond_block, "when")
                if when_block is not None:  # ==> find "case" => "when"
                    # verify that it matches
                    is_verified = True
                    for verify in self._verifies:
                        if not verify(cfg, when_block):
                            is_verified = False
                            break
                    # if any one of the verification fails, skip
                    if not is_verified:
                        continue
                    # all items are verified
                    return utils.get_item(cond_block, "then", default=default)  # ==> find "case" "when" "then"
                # if it is a else block
                else_block = utils.get_item(cond_block, "else")
                if else_block is not None:  # ==> find "case" => "else"
                    return else_block
            # use default value
            return default  # ==> not found "else"

        # use config value
        return value  # ==> not found "case"

    @classmethod
    def _get_verify(cls, item: str):
        def verify(config, when_block):
            when_scope = utils.get_item(when_block, item)
            if when_scope is not None:
                value = config[item]
                if isinstance(when_scope, str):
                    if value != when_scope:
                        return False
                elif isinstance(when_scope, (tuple, list, set)):
                    if value not in when_scope:
                        return False
            return True

        return verify


class Var(object):

    def __init__(self, name=None, default=None):
        self.name = name
        self.default = default


class Meta(type):

    def __new__(mcs, name, bases, attrs):
        # initialize __parser__
        attrs["__parser__"] = Parser(
            "system",
            "processor",
            "architecture",
        )
        # initialize __default__
        attrs["__default__"] = {}
        for key in list(attrs.keys()):
            if isinstance(attrs[key], Var):
                var = attrs[key]
                var_name = var.name or key
                attrs["__default__"][var_name] = var.default
                attrs[key] = property(mcs.make_fget(var_name))
        return type.__new__(mcs, name, bases, attrs)

    @classmethod
    def make_fget(mcs, key):
        return lambda self: self.config.get(key)


class GeneralTool(metaclass=Meta):
    __default__: Dict
    __parser__: Parser

    name: str = Var(default="")
    version: str = Var(default="")
    download_url: str = Var(default="")
    dummy_path: bool = Var(default=False)
    root_path: str = Var(default="")
    unpack_path: str = Var(default="")
    absolute_path: str = Var(default="")
    executable: bool = Var(default=True)
    executable_cmdline: tuple = Var(default=[])

    exists: bool = property(lambda self: self.dummy_path or os.path.exists(self.absolute_path))
    dirname: bool = property(lambda self: None if self.dummy_path else os.path.dirname(self.absolute_path))

    def __init__(self, container: "GeneralTools", cfg: Union[dict, str], **kwargs):
        self.__container = container
        self.__config = cfg

        self._raw_config = self.__default__.copy()
        self._raw_config.update(container.config)
        self._raw_config.update(cfg)
        self._raw_config.update(kwargs)

    @cached_property
    def config(self) -> dict:
        cfg = self.__parser__.parse(self._raw_config)

        # download url
        download_url = utils.get_item(cfg, "download_url") or ""
        assert isinstance(download_url, str), \
            f"{cfg['name']}.download_url type error, " \
            f"str was expects, got {type(download_url)}"

        cfg["download_url"] = download_url.format(tools=self.__container, **cfg)

        unpack_path = utils.get_item(cfg, "unpack_path") or ""
        assert isinstance(unpack_path, str), \
            f"{cfg['name']}.unpack_path type error, " \
            f"str was expects, got {type(unpack_path)}"

        target_path = utils.get_item(cfg, "target_path", type=str) or ""
        assert isinstance(target_path, str), \
            f"{cfg['name']}.target_path type error, " \
            f"str was expects, got {type(target_path)}"

        # target path: {target_path}
        # unpack path: {unpack_path}
        # root path: tools/{unpack_path}/
        # absolute path: tools/{unpack_path}/{target_path}
        cfg["target_path"] = target_path.format(tools=self.__container, **cfg)
        cfg["unpack_path"] = unpack_path.format(tools=self.__container, **cfg)
        paths = ["tools"]
        if not utils.is_empty(cfg["unpack_path"]):
            paths.append(cfg["unpack_path"])
        cfg["root_path"] = resource.get_data_dir(*paths)
        cfg["absolute_path"] = os.path.join(cfg["root_path"], cfg["target_path"])

        # set executable cmdline
        cmdline = utils.get_item(cfg, "cmdline", type=str) or ""
        if not utils.is_empty(cmdline):
            cmdline = shutil.which(cmdline)
        if not utils.is_empty(cmdline):
            cfg["absolute_path"] = cmdline
            cfg["executable_cmdline"] = [cmdline]
        else:
            executable_cmdline = utils.get_item(cfg, "executable_cmdline")
            if executable_cmdline:
                assert isinstance(executable_cmdline, (str, tuple, list)), \
                    f"{cfg['name']}.executable_cmdline type error, " \
                    f"str/tuple/list was expects, got {type(executable_cmdline)}"
                # if executable_cmdline is not empty,
                # set the executable flag to false
                cfg["executable"] = False
            else:
                # if executable_cmdline is empty,
                # set absolute_path as executable_cmdline
                executable_cmdline = cfg["absolute_path"]
            if isinstance(executable_cmdline, str):
                executable_cmdline = [executable_cmdline]
            cfg["executable_cmdline"] = [str(i).format(tools=self.__container, **cfg) \
                                         for i in executable_cmdline]

        return cfg

    def copy(self, **kwargs):
        return GeneralTool(self.__container, self.__config, **kwargs)

    def prepare(self) -> None:
        # download and unzip file
        if self.exists:
            pass
        elif not self.download_url:
            raise Exception(f"{self.name} does not support running on {self.__container.system}")
        elif not self.exists:
            logger.info("Download tool: {}".format(self.download_url))
            url_file = urlutils.UrlFile(self.download_url)
            temp_dir = resource.get_temp_path("tools", "cache")
            temp_path = url_file.save(save_dir=temp_dir)
            if not utils.is_empty(self.unpack_path):
                logger.debug("Unpack tool to {}".format(self.root_path))
                shutil.unpack_archive(temp_path, self.root_path)
                os.remove(temp_path)
            else:
                logger.debug("Move tool to {}".format(self.absolute_path))
                os.rename(temp_path, self.absolute_path)

        # change tool file mode
        if self.executable and not os.access(self.absolute_path, os.X_OK):
            logger.debug(f"Chmod 755 {self.absolute_path}")
            os.chmod(self.absolute_path, 0o0755)

    def clear(self) -> None:
        if not self.exists:
            logger.debug(f"{self} does not exist, skip")
            return
        if not utils.is_empty(self.unpack_path):
            logger.debug(f"Delete {self.root_path}")
            shutil.rmtree(self.root_path, ignore_errors=True)
        elif self.absolute_path.startswith(self.root_path):
            logger.debug(f"Delete {self.absolute_path}")
            os.remove(self.absolute_path)

    def _process(self, fn, *args, **kwargs):
        self.prepare()

        # python
        executable_cmdline = self.executable_cmdline
        if executable_cmdline[0] == "python":
            args = [sys.executable, *executable_cmdline[1:], *args]
            return fn(*args, **kwargs)

        # java or other
        if executable_cmdline[0] in self.__container.items:
            args = [*executable_cmdline[1:], *args]
            tool: GeneralTool = self.__container.items[executable_cmdline[0]]
            return tool._process(fn, *args, **kwargs)

        return fn(*[*executable_cmdline, *args], **kwargs)

    def popen(self, *args: [str], **kwargs) -> subprocess.Popen:
        return self._process(utils.popen, *args, **kwargs)

    def exec(self, *args: [str], **kwargs) -> (subprocess.Popen, str, str):
        return self._process(utils.exec, *args, **kwargs)

    def __repr__(self):
        return f"<GeneralTool {self.name}>"


class GeneralTools(object):
    system = property(lambda self: self.config["system"])
    processor = property(lambda self: self.config["processor"])
    architecture = property(lambda self: self.config["architecture"])

    def __init__(self, **kwargs):
        self.config = kwargs
        self.config.setdefault("system", platform.system().lower())
        self.config.setdefault("processor", platform.processor().lower())
        self.config.setdefault("architecture", platform.architecture()[0].lower())

    @cached_property
    def items(self) -> Mapping[str, GeneralTool]:
        items = {}
        for key, value in config.get_namespace("GENERAL_TOOL_").items():
            if not isinstance(value, dict):
                warnings.warn(f"dict was expected, got {type(value)}, ignored.")
                continue
            name = value.setdefault("name", key)
            items[name] = GeneralTool(self, value)
        return items

    def __iter__(self) -> Iterator[GeneralTool]:
        return iter(self.items.values())

    def __getitem__(self, item) -> Union[GeneralTool, None]:
        return self.items[item] if item in self.items else None

    def __getattr__(self, item) -> Union[GeneralTool, None]:
        return self.items[item] if item in self.items else None
