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
import warnings

from . import utils
from .decorator import cached_property

_default_config = {
    "name": "",
    "cmdline": "",
    "download_url": "",
    "unpack_path": "",
    "target_path": "",
    "root_path": "",
    "absolute_path": "",
    "executable": int(time.time()),  # True or False (default: True)
    "executable_cmdline": [],
}


class GeneralTool(object):

    def __init__(self, container, name: str, config: dict):
        self._container = container
        self._raw_config = _default_config.copy()
        self._raw_config.update(container.config)
        self._raw_config.update(name=name)
        self._raw_config.update(config)

        self._verifiers = (
            self._get_verifier("system"),
            self._get_verifier("processor"),
            self._get_verifier("architecture")
        )

    @cached_property
    def config(self) -> dict:
        from .environ import resource

        config = {k: v for k, v in self._raw_config.items()}

        # download url
        download_url = self._get_raw_item("download_url", type=str) or ""
        config["download_url"] = download_url.format(
            tools=self._container,
            **config
        )

        # unpack path
        unpack_path = self._get_raw_item("unpack_path", type=str) or ""
        config["unpack_path"] = unpack_path.format(
            tools=self._container,
            **config
        )

        # root path: tools/{unpack_path}/
        paths = ["tools"]
        if not utils.is_empty(config["unpack_path"]):
            paths.append(config["unpack_path"])
        config["root_path"] = resource.get_data_dir(
            *paths
        )

        # file path: tools/{unpack_path}/{target_path}
        target_path = self._get_raw_item("target_path", type=str) or ""
        config["target_path"] = target_path.format(
            tools=self._container,
            **config
        )
        config["absolute_path"] = os.path.join(
            config["root_path"],
            config["target_path"]
        )

        # is it executable
        config["executable"] = self._get_raw_item("executable", type=bool)

        # set executable cmdline
        cmdline = (self._get_raw_item("cmdline", type=str) or "")
        if not utils.is_empty(cmdline):
            cmdline = shutil.which(cmdline)
        if not utils.is_empty(cmdline):
            config["absolute_path"] = cmdline
            config["executable_cmdline"] = [cmdline]
        else:
            executable_cmdline = (self._get_raw_item("executable_cmdline") or [config["absolute_path"]])
            if isinstance(executable_cmdline, str):
                executable_cmdline = [executable_cmdline]
            for i in range(len(executable_cmdline)):
                executable_cmdline[i] = str(executable_cmdline[i]).format(tools=self._container, **config)
            config["executable_cmdline"] = executable_cmdline

        return config

    @property
    def exists(self) -> bool:
        return os.path.exists(self.absolute_path)

    @property
    def dirname(self) -> str:
        return os.path.dirname(self.absolute_path)

    def prepare(self, force_download=False) -> None:
        from .environ import logger, resource

        # remove tool files first
        if force_download:
            self.clear()

        if self.exists:
            pass
        elif not self.download_url:
            warnings.warn("download url is empty, skipped.")
        else:
            # download tool files
            file = resource.get_temp_path(
                "tools",
                utils.get_md5(self.download_url),
                utils.guess_file_name(self.download_url),
                create_parent=True
            )
            logger.info("download: {}".format(self.download_url))
            utils.download(self.download_url, file)
            if not os.path.exists(self.root_path):
                os.makedirs(self.root_path)
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

    def _process(self, fn, *args, **kwargs):
        self.prepare(force_download=False)
        executable_cmdline = self.executable_cmdline
        if executable_cmdline[0] == "python":
            args = [sys.executable, *executable_cmdline[1:], *args]
            return fn(*args, **kwargs)
        if executable_cmdline[0] in self._container.items:
            args = [*executable_cmdline[1:], *args]
            tool: GeneralTool = self._container.items[executable_cmdline[0]]
            return tool._process(fn, *args, **kwargs)
        return fn(*[*executable_cmdline, *args], **kwargs)

    def popen(self, *args: [str], **kwargs: dict) -> subprocess.Popen:
        return self._process(utils.popen, *args, **kwargs)

    def exec(self, *args: [str], **kwargs: dict) -> (subprocess.Popen, str, str):
        return self._process(utils.exec, *args, **kwargs)

    def __getattr__(self, item):
        return self.config.get(item)

    @classmethod
    def _get_verifier(cls, item: str):
        def verify(self, when_block):
            when_scope = utils.get_item(when_block, item)
            if when_scope is not None:
                value = self._container.config[item]
                if isinstance(when_scope, str):
                    if value != when_scope:
                        return False
                elif isinstance(when_scope, (tuple, list, set)):
                    if value not in when_scope:
                        return False
            return True

        return verify

    def _get_raw_item(self, key: str, type=None, default=None):
        value = utils.get_item(self._raw_config, key, default=default)
        if isinstance(value, dict) and "case" in value:
            case_block = value.get("case")

            # traverse all blocks
            for cond_block in case_block:

                # if it is a when block
                when_block = utils.get_item(cond_block, "when")
                if when_block is not None:
                    # check if the system matches
                    is_verified = True
                    for verify in self._verifiers:
                        if not verify(self, when_block):
                            is_verified = False
                            break
                    # if any one of the verification fails, skip
                    if not is_verified:
                        continue
                    # all items are verified
                    return utils.get_item(cond_block, "then", type=type, default=default)

                # if it is a else block
                else_block = utils.get_item(cond_block, "else")
                if else_block is not None:
                    return utils.get_item(else_block, type=type, default=default)

            # use default value
            return utils.get_item(default, type=type, default=default)

        # use config value
        return utils.get_item(value, type=type, default=default)


class GeneralTools(object):

    def __init__(self, **kwargs):
        self.config = kwargs
        self.config.setdefault("system", platform.system().lower())
        self.config.setdefault("processor", platform.processor().lower())
        self.config.setdefault("architecture", platform.architecture()[0].lower())

    @cached_property
    def items(self) -> typing.Mapping[str, GeneralTool]:
        from . import config
        items = {}
        for key, value in config.get_namespace("GENERAL_TOOL_").items():
            if isinstance(value, dict):
                name = value.get("name") or key
                items[name] = GeneralTool(self, name, value)
        return items

    @property
    def system(self):
        return self.config["system"]

    @property
    def processor(self):
        return self.config["processor"]

    @property
    def architecture(self):
        return self.config["architecture"]

    def __iter__(self) -> typing.Iterator[GeneralTool]:
        return iter(self.items.values())

    def __getitem__(self, item) -> typing.Union[GeneralTool, None]:
        return self.items[item] if item in self.items else None

    def __getattr__(self, item) -> typing.Union[GeneralTool, None]:
        return self.items[item] if item in self.items else None
