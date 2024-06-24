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
   /  oooooooooooooooo  .o.  oooo /,   `,"-----------
  / ==ooooooooooooooo==.o.  ooo= //   ,``--{)B     ,"
 /_==__==========__==_ooo__ooo=_/'   /___________,"
"""

import os
import pickle
import shutil
import sys
import warnings
from typing import TYPE_CHECKING, Dict, Iterator, Any, Tuple, List, Type, Optional, Generator

from . import utils
from .decorator import cached_property
from .metadata import __missing__

if TYPE_CHECKING:
    from ._environ import BaseEnviron

SUPPRESS = object()
VALIDATE_KEYS = set()
INTERNAL_KEYS = set()


def _parse_value(config: Dict[str, Any], key: str, default=None):
    value = utils.get_item(config, key, default=default)
    if not isinstance(value, dict):
        # not found "when", use config value
        return value

    # parse when block:
    # -----------------------------------------
    #   field:
    #     when:                                 <== when_block
    #       - system: [darwin, linux]
    #         then: xxx
    #       - system: windows
    #         then: yyy
    #       - else: ~
    # -----------------------------------------
    when_block = utils.get_item(value, "when", default=SUPPRESS)
    if when_block is SUPPRESS or not isinstance(when_block, (tuple, list)):
        # not found "when", use default value
        return value

    for cond_block in when_block:
        # -----------------------------------------
        #   field:
        #     when:
        #       - system: [darwin, linux]
        #         then: xxx                         <== then_block
        #       - system: windows
        #         then: yyy
        #       - else: ~
        # -----------------------------------------
        value = utils.get_item(cond_block, "then", default=SUPPRESS)
        if value != SUPPRESS:
            for key in VALIDATE_KEYS:
                # parse validate block:
                # -----------------------------------------
                #   field:
                #     when:
                #       - system: [darwin, linux]           <== validate_block
                #         then: xxx
                #       - system: windows
                #         then: yyy
                #       - else: ~
                # -----------------------------------------
                choice = utils.get_item(cond_block, key, default=SUPPRESS)
                if choice is not SUPPRESS:
                    if isinstance(choice, str):
                        if config[key] != choice:
                            break
                    elif isinstance(choice, (tuple, list, set)):
                        if config[key] not in choice:
                            break
            else:
                # all keys are verified, return "then"
                return value

        # -----------------------------------------
        #   field:
        #     when:
        #       - system: [darwin, linux]
        #         then: xxx
        #       - system: windows
        #         then: yyy
        #       - else: ~                           <== else_block
        # -----------------------------------------
        value = utils.get_item(cond_block, "else", default=SUPPRESS)
        if value != SUPPRESS:
            # if it is an else block, return "else"
            return value

    # use default value
    return default  # ==> not found "else"


class ToolProperty(object):

    def __init__(self, name=None, raw: bool = False, default: Any = None,
                 internal: bool = False, validate: bool = False):
        self.name = name
        self.raw = raw
        self.default = default
        self.internal = internal
        self.validate = validate


class ToolMeta(type):

    def __new__(mcs, name, bases, attrs):
        attrs["__default__"] = default = {}
        for key in list(attrs.keys()):
            if isinstance(attrs[key], ToolProperty):
                prop: ToolProperty = attrs[key]
                prop_name = prop.name or key
                if prop.validate:
                    VALIDATE_KEYS.add(prop_name)
                if prop.internal:
                    INTERNAL_KEYS.add(prop_name)
                default[prop_name] = prop.default
                attrs[key] = mcs._make_property(prop, prop_name)
        return type.__new__(mcs, name, bases, attrs)

    @classmethod
    def _make_property(mcs, prop: ToolProperty, name: str):
        return property(lambda self: self._raw_config.get(name)) \
            if prop.raw \
            else property(lambda self: self.config.get(name))


class ToolError(Exception):
    pass


class ToolNotFound(ToolError):
    pass


class ToolNotSupport(ToolError):
    pass


class ToolExecError(ToolError):
    pass


class Tool(metaclass=ToolMeta):
    __default__: Dict

    name: str = ToolProperty(default=__missing__, raw=True, internal=True)
    system: str = ToolProperty(default=__missing__, raw=True, internal=True, validate=True)
    machine: str = ToolProperty(default=__missing__, raw=True, internal=True, validate=True)
    version: str = ToolProperty(default="", raw=True)
    depends_on: tuple = ToolProperty(default=[], internal=True)
    download_url: str = ToolProperty(default=__missing__)
    target_path: bool = ToolProperty(default=__missing__, internal=True)
    root_path: str = ToolProperty(default=__missing__, internal=True)
    unpack_path: str = ToolProperty(default=__missing__, internal=True)
    absolute_path: str = ToolProperty(default=__missing__, internal=True)
    cmdline: str = ToolProperty(default=__missing__)
    executable_cmdline: tuple = ToolProperty(default=[], internal=True)
    environment: Dict[str, str] = ToolProperty(default={}, internal=True)

    def __init__(self, tools: "Tools", name: str, config: Dict[str, Any], **kwargs):
        self._tools = tools
        self._config = config

        self._raw_config: Dict = pickle.loads(pickle.dumps(self.__default__))
        self._raw_config.update(config)

        # set default value
        if self._raw_config.get("name") == __missing__:
            self._raw_config["name"] = name
        if self._raw_config.get("system") == __missing__:
            self._raw_config["system"] = self._tools.environ.system
        if self._raw_config.get("machine") == __missing__:
            self._raw_config["machine"] = self._tools.environ.machine

        # set value from environment
        prefix = self.name.replace("-", "_")
        for key, value in self._raw_config.items():
            if key not in INTERNAL_KEYS:
                new_value = self._tools.config.get(f"{prefix}_{key}".upper(), default=None)
                if new_value is not None:
                    self._raw_config[key] = new_value

        self._raw_config.update(kwargs)

    @cached_property
    def config(self) -> dict:
        config = {
            key: _parse_value(self._raw_config, key)
            for key in self._raw_config
        }

        depends_on = utils.get_item(config, "depends_on") or []
        assert isinstance(depends_on, (str, Tuple, List)), \
            f"{self} depends_on type error, " \
            f"str/tuple/list was expects, got {type(depends_on)}"
        if isinstance(depends_on, str):
            depends_on = [depends_on]
        for dependency in depends_on:
            assert dependency in self._tools.all, \
                f"{self}.depends_on error: not found Tool<{dependency}>"
        config["depends_on"] = depends_on

        # download url
        download_url = utils.get_item(config, "download_url") or ""
        if download_url == __missing__:
            download_url = ""
        assert isinstance(download_url, str), \
            f"{self} download_url type error, " \
            f"str was expects, got {type(download_url)}"
        config["download_url"] = download_url.format(tools=self._tools, **config)

        unpack_path = utils.get_item(config, "unpack_path") or ""
        if unpack_path == __missing__:
            unpack_path = ""
        assert isinstance(unpack_path, str), \
            f"{self} unpack_path type error, " \
            f"str was expects, got {type(unpack_path)}"

        target_path = utils.get_item(config, "target_path") or ""
        if target_path == __missing__:
            target_path = ""
        assert isinstance(target_path, str), \
            f"{self} target_path type error, " \
            f"str was expects, got {type(target_path)}"

        absolute_path = utils.get_item(config, "absolute_path") or ""
        if absolute_path == __missing__:
            absolute_path = ""
        assert isinstance(absolute_path, str), \
            f"{self} absolute_path type error, " \
            f"str was expects, got {type(absolute_path)}"

        if download_url and not unpack_path and not target_path:
            target_path = utils.guess_file_name(download_url)

        # target path: {target_path}
        # unpack path: {unpack_path}
        # root path: {data_path}/tools/{unpack_path}/
        # absolute path: {data_path}/tools/{unpack_path}/{target_path}
        config["target_path"] = target_path = target_path.format(tools=self._tools, **config)
        config["unpack_path"] = unpack_path = unpack_path.format(tools=self._tools, **config)
        paths = ["tools"]
        if not utils.is_empty(unpack_path):
            paths.append(unpack_path)
        else:
            paths.append(
                f"{self.name}-{self.version}"
                if self.version
                else self.name
            )
        config["root_path"] = root_path = self._tools.environ.get_data_dir(*paths)

        if absolute_path:
            config["absolute_path"] = absolute_path.format(tools=self._tools, **config)
        elif config["target_path"]:
            config["absolute_path"] = os.path.join(root_path, target_path)
        else:
            config["absolute_path"] = ""

        # set executable cmdline
        cmdline = utils.get_item(config, "cmdline") or ""
        if cmdline == __missing__:
            cmdline = config["name"]
        assert isinstance(cmdline, str), \
            f"{self} cmdline type error, " \
            f"str was expects, got {type(cmdline)}"
        config["cmdline"] = cmdline

        if not utils.is_empty(cmdline):
            cmdline = shutil.which(cmdline)
        if not utils.is_empty(cmdline):
            config["absolute_path"] = cmdline
            config["executable_cmdline"] = [cmdline]
        else:
            executable_cmdline = utils.get_item(config, "executable_cmdline")
            if executable_cmdline:
                assert isinstance(executable_cmdline, (str, tuple, list)), \
                    f"{self} executable_cmdline type error, " \
                    f"str/tuple/list was expects, got {type(executable_cmdline)}"
            else:
                # if executable_cmdline is empty,
                # set absolute_path as executable_cmdline
                executable_cmdline = config["absolute_path"]
            if isinstance(executable_cmdline, str):
                executable_cmdline = [executable_cmdline]
            config["executable_cmdline"] = [
                str(cmd).format(tools=self._tools, **config)
                for cmd in executable_cmdline
            ]

        return config

    @property
    def supported(self) -> bool:
        return True if self.exists or self.absolute_path else False

    @property
    def exists(self) -> bool:
        return True if self.absolute_path and os.path.exists(self.absolute_path) else False

    @property
    def dirname(self) -> Optional[str]:
        return None if not self.absolute_path else os.path.dirname(self.absolute_path)

    @property
    def executable(self) -> bool:
        cmdline = self.executable_cmdline
        path = cmdline[0] if cmdline else ""
        if self.absolute_path == path:
            if self.root_path == os.path.commonpath([self.root_path, path]):
                return True
        return False

    def get(self, key: str, default: Any = None) -> Any:
        value = self.config.get(key, default)
        if isinstance(value, str):
            value = value.format(tools=self._tools, **self.config)
        return value

    def copy(self, **kwargs) -> "Tool":
        return Tool(self._tools, self.name, self._config, **kwargs)

    def prepare(self) -> None:
        if not self.supported:
            raise ToolNotSupport(
                f"{self} does not support on "
                f"{self._tools.environ.system} ({self._tools.environ.machine})")

        for dependency in self.depends_on:
            tool = self._tools[dependency]
            tool.prepare()

        # download and unzip file
        if not self.exists:
            self._tools.logger.info(f"Download {self}: {self.download_url}")
            url_file = self._tools.environ.get_url_file(self.download_url)
            temp_dir = self._tools.environ.get_temp_path("tools", "cache")
            temp_path = url_file.save(temp_dir)
            if not utils.is_empty(self.unpack_path):
                self._tools.logger.debug(f"Unpack {self} to {self.root_path}")
                os.makedirs(self.root_path, exist_ok=True)
                shutil.unpack_archive(temp_path, self.root_path)
                os.remove(temp_path)
            else:
                self._tools.logger.debug(f"Move {self} to {self.absolute_path}")
                os.makedirs(self.root_path, exist_ok=True)
                shutil.move(temp_path, self.absolute_path)

        # change tool file mode
        if self.executable and not os.access(self.absolute_path, os.X_OK):
            self._tools.logger.debug(f"Chmod 755 {self.absolute_path}")
            os.chmod(self.absolute_path, 0o0755)

    def clear(self) -> None:
        if not self.exists:
            self._tools.logger.debug(f"{self} does not exist, skip")
            return
        if not utils.is_empty(self.unpack_path):
            self._tools.logger.debug(f"Delete {self.root_path}")
            shutil.rmtree(self.root_path, ignore_errors=True)
        elif not utils.is_empty(self.root_path):
            self._tools.logger.debug(f"Delete {self.root_path}")
            shutil.rmtree(self.root_path, ignore_errors=True)

    def popen(self, *args: [Any], **kwargs) -> utils.Process:
        self.prepare()

        if self.environment:
            env = kwargs.get("default_env", {})
            for key, value in self.environment.items():
                env.setdefault(key, value)
            kwargs["default_env"] = env

        # java or other
        executable_cmdline = self.executable_cmdline
        if executable_cmdline[0] in self._tools.all:
            args = [*executable_cmdline[1:], *args]
            tool = self._tools[executable_cmdline[0]]
            return tool.popen(*args, **kwargs)

        return utils.Process(*[*executable_cmdline, *args], **kwargs)

    @utils.timeoutable
    def exec(
            self,
            *args: [Any],
            timeout: utils.Timeout = None,
            ignore_errors: bool = False,
            log_output: bool = False,
            error_type: Type[Exception] = ToolExecError
    ) -> str:
        """
        执行命令
        :param args: 命令
        :param timeout: 超时时间
        :param ignore_errors: 忽略错误，报错不会抛异常
        :param log_output: 把输出打印到logger中
        :param error_type: 抛出异常类型
        :return: 返回stdout输出内容
        """
        process = self.popen(*args, capture_output=True)

        try:
            out, err = process.exec(
                timeout=timeout,
                on_stdout=self._tools.logger.info if log_output else None,
                on_stderr=self._tools.logger.error if log_output else None
            )
            if not ignore_errors and process.poll() not in (0, None):
                if isinstance(err, bytes):
                    err = err.decode(errors="ignore")
                    err = err.strip()
                elif isinstance(err, str):
                    err = err.strip()
                if err:
                    raise error_type(err)

            if isinstance(out, bytes):
                out = out.decode(errors="ignore")
                out = out.strip()
            elif isinstance(out, str):
                out = out.strip()

            return out or ""

        finally:
            process.kill()

    def __repr__(self):
        return f"Tool<{self.name}>"


class Tools(object):

    def __init__(self, environ: "BaseEnviron", config: Dict[str, Dict]):
        self.environ = environ
        self.logger = environ.get_logger("tools")
        self.config = environ.wrap_config(prefix="")
        self.all = self._parse_items(config)

    @property
    def env_path(self) -> List[str]:
        paths = []
        for tool in self:
            if tool.executable:
                path = tool.dirname
                if path and path not in paths:
                    paths.append(path)
        return paths

    def keys(self) -> Generator[str, None, None]:
        for k, v in self.all.items():
            if v.supported:
                yield k

    def values(self) -> Generator[Tool, None, None]:
        for k, v in self.all.items():
            if v.supported:
                yield v

    def items(self) -> Generator[Tuple[str, Tool], None, None]:
        for k, v in self.all.items():
            if v.supported:
                yield k, v

    def __iter__(self) -> Iterator[Tool]:
        return iter([t for t in self.all.values() if t.supported])

    def __getitem__(self, item: str) -> Tool:
        tool = self.all.get(item, None)
        if tool is None:
            raise ToolNotFound(f"Not found tool {item}")
        if not tool.supported:
            raise ToolNotSupport(
                f"{tool} does not support on "
                f"{self.environ.system} ({self.environ.machine})")
        return tool

    def __getattr__(self, item: str) -> Tool:
        return self[item]

    def __setitem__(self, key: str, value: Tool):
        self.all[key] = value

    def _parse_items(self, config: Dict[str, Dict]) -> Dict[str, Tool]:
        result = {
            "shell": Tool(self, "shell", {
                "cmdline": None,
                "absolute_path": utils.get_shell_path(),
            }),
            "python": Tool(self, "python", {
                "cmdline": None,
                "absolute_path": sys.executable,
            }),
        }

        for key, value in config.items():
            if not isinstance(value, dict):
                warnings.warn(f"dict was expected, got {type(value)}, ignored.")
                continue
            name = value.get("name", None)
            if name is None:
                if key.startswith("TOOL_"):
                    key = key[len("TOOL_"):]
                name = value["name"] = key.lower()
            result[name] = Tool(self, name, value)

        return result
