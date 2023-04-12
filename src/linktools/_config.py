#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : config.py 
@time    : 2021/08/04
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

__all__ = ("Config",)

import abc
import errno
import os
from types import ModuleType
from typing import Optional, Union, Callable, IO, Any, Mapping, Dict, List, Type

from rich.prompt import Prompt, IntPrompt, FloatPrompt

from . import utils
from ._environ import BaseEnviron


class _Loader(abc.ABC):

    def load(self, env: BaseEnviron, key: any):
        try:
            return self._load(env, key)
        except Exception as e:
            env.logger.error(f"Load config \"{key}\" error", exc_info=e)
            raise e

    @abc.abstractmethod
    def _load(self, env: BaseEnviron, key: any):
        pass


class _Prompt(_Loader):

    def __init__(
            self,
            prompt: str = None,
            password: bool = False,
            choices: Optional[List[str]] = None,
            default: Any = None,
            type: Type = str,
            cached: bool = None,
            trim: bool = True,
    ):
        self.prompt = prompt
        self.password = password
        self.choices = choices
        self.default = default
        self.cached = cached
        self.type = type
        self.trim = trim

    def _load(self, env: BaseEnviron, key: any):
        if issubclass(self.type, str):
            prompt = Prompt
        elif issubclass(self.type, int):
            prompt = IntPrompt
        elif issubclass(self.type, float):
            prompt = FloatPrompt
        else:
            raise NotImplementedError("prompt only supports three types of str, int, float")

        def process_result(data):
            if self.trim and isinstance(data, str):
                data = data.strip()
            if self.type and not isinstance(data, self.type):
                data = self.type(data)
                if self.trim and isinstance(data, str):
                    data = data.strip()
            return data

        if not self.cached:
            return process_result(
                prompt.ask(
                    self.prompt or f"Please input {key}",
                    password=self.password,
                    choices=self.choices,
                    default=self.default,
                    show_default=True,
                    show_choices=True
                )
            )

        default = self.default

        path = env.get_data_path("configs", f"cached_{env.name}", str(key), create_parent=True)
        if os.path.exists(path):
            try:
                with open(path, "rt") as fd:
                    default = process_result(fd.read())
                if not env.get_config("RELOAD_CONFIG", type=utils.bool, default=False):
                    return default
            except Exception as e:
                env.logger.debug(f"Load cached config \"key\" error: {e}")

        result = process_result(
            prompt.ask(
                self.prompt or f"Please input {key}",
                password=self.password,
                choices=self.choices,
                default=default,
                show_default=True,
                show_choices=True
            )
        )

        with open(path, "wt") as fd:
            fd.write(str(result))

        return result


class _Lazy(_Loader):

    def __init__(self, func: Callable[[BaseEnviron], Any]):
        self.func = func

    def _load(self, env: BaseEnviron, key: any):
        return self.func(env)


# Code stolen from flask.Config
class Config(dict):

    def __init__(self, env: BaseEnviron, defaults: Optional[dict] = None):
        super().__init__(defaults or {})
        self.environ = env

    def from_envvar(self, variable_name: str, silent: bool = False) -> bool:
        rv = os.environ.get(variable_name)
        if not rv:
            if silent:
                return False
            raise RuntimeError(
                f"The environment variable {variable_name!r} is not set"
                " and as such configuration could not be loaded. Set"
                " this variable and make it point to a configuration"
                " file"
            )
        return self.from_pyfile(rv, silent=silent)

    def from_pyfile(self, filename: str, silent: bool = False) -> bool:
        d = ModuleType("config")
        d.__file__ = filename
        d.prompt = _Prompt
        d.lazy = _Lazy
        try:
            with open(filename, "rb") as config_file:
                exec(compile(config_file.read(), filename, "exec"), d.__dict__)
        except OSError as e:
            if silent and e.errno in (errno.ENOENT, errno.EISDIR, errno.ENOTDIR):
                return False
            e.strerror = f"Unable to load configuration file ({e.strerror})"
            raise
        self.from_object(d)
        return True

    def from_object(self, obj: Union[object, str]) -> None:
        for key in dir(obj):
            if key[0].isupper():
                self[key] = getattr(obj, key)

    def from_file(self, filename: str, load: Callable[[IO[Any]], Mapping], silent: bool = False) -> bool:
        try:
            with open(filename, "rb") as f:
                obj = load(f)
        except OSError as e:
            if silent and e.errno in (errno.ENOENT, errno.EISDIR):
                return False

            e.strerror = f"Unable to load configuration file ({e.strerror})"
            raise

        return self.from_mapping(obj)

    def from_mapping(self, mapping: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> bool:
        mappings: Dict[str, Any] = {}
        if mapping is not None:
            mappings.update(mapping)
        mappings.update(kwargs)
        for key, value in mappings.items():
            if key[0].isupper():
                self[key] = value
        return True

    def __setitem__(self, key, value):
        if isinstance(value, _Loader):
            value = utils.lazy_load(value.load, self.environ, key)
        return super().__setitem__(key, value)
