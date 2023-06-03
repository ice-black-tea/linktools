#!/usr/bin/env python3
# -*- coding:utf-8 -*-

"""
@author  : Hu Ji
@file    : _config.py
@time    : 2023/05/20
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

import abc
import errno
import json
import os
import pickle
import threading
from types import ModuleType
from typing import Type, Optional, Any, Dict, Generator, Tuple, Callable, IO, Mapping, Union, List

from rich.prompt import Prompt, IntPrompt, FloatPrompt, Confirm, PromptType, InvalidResponse

from . import utils
from ._environ import BaseEnviron, MISSING, T


class ConfigLoader(abc.ABC):
    __lock__ = threading.RLock()

    def __init__(self):
        self._data: Union[str, object] = MISSING

    def load(self, env: BaseEnviron, key: Any) -> Optional[str]:
        if self._data is not MISSING:
            return self._data
        with self.__lock__:
            if self._data is MISSING:
                self._data = self._load(env, key)
        return self._data

    @abc.abstractmethod
    def _load(self, env: BaseEnviron, key: Any):
        pass


class ConfigDict(dict):

    def update_from_pyfile(self, filename: str, silent: bool = False) -> bool:
        d = ModuleType("config")
        d.__file__ = filename
        d.prompt = Config.Prompt
        d.lazy = Config.Lazy
        d.error = Config.Error
        d.confirm = Config.Confirm
        try:
            with open(filename, "rb") as config_file:
                exec(compile(config_file.read(), filename, "exec"), d.__dict__)
        except OSError as e:
            if silent and e.errno in (errno.ENOENT, errno.EISDIR, errno.ENOTDIR):
                return False
            e.strerror = f"Unable to load configuration file ({e.strerror})"
            raise
        self.update_from_object(d)
        return True

    def update_from_file(self, filename: str, load: Callable[[IO[Any]], Mapping], silent: bool = False) -> bool:
        try:
            with open(filename, "rb") as f:
                obj = load(f)
        except OSError as e:
            if silent and e.errno in (errno.ENOENT, errno.EISDIR):
                return False

            e.strerror = f"Unable to load configuration file ({e.strerror})"
            raise

        return self.update_from_mapping(obj)

    def update_from_object(self, obj: Union[object, str]) -> None:
        for key in dir(obj):
            if key[0].isupper():
                self[key] = getattr(obj, key)

    def update_from_mapping(self, mapping: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> bool:
        mappings: Dict[str, Any] = {}
        if mapping is not None:
            mappings.update(mapping)
        mappings.update(kwargs)
        for key, value in mappings.items():
            if key[0].isupper():
                self[key] = value
        return True


class Config:

    def __init__(self, env: BaseEnviron, internal: ConfigDict):
        self._environ = env
        self._internal = internal
        self._config = pickle.loads(pickle.dumps(self._internal))
        self._envvar_prefix = f"{self._environ.name.upper()}_"

    @property
    def envvar_prefix(self):
        """
        环境变量前缀
        """
        return self._envvar_prefix

    @envvar_prefix.setter
    def envvar_prefix(self, value: str):
        """
        环境变量前缀
        """
        self._envvar_prefix = value

    def get_namespace(self, namespace: str, lowercase: bool = True, trim_namespace: bool = True) -> Dict[str, Any]:
        """
        根据命名空间获取配置列表
        """
        rv = {}
        for k in self._config:
            if not k.startswith(namespace):
                continue
            if trim_namespace:
                key = k[len(namespace):]
            else:
                key = k
            if lowercase:
                key = key.lower()
            rv[key] = self.get(k)
        return rv

    def get(self, key: str, type: Type[T] = None, default: T = MISSING) -> Optional[T]:
        """
        获取指定配置，优先会从环境变量中获取
        """
        last_error = None
        try:

            env_key = f"{self.envvar_prefix}{key}"
            if env_key in os.environ:
                value = os.environ.get(env_key)
                return value if type is None else type(value)

            if key in self._config:
                value = self._config.get(key)
                if isinstance(value, ConfigLoader):
                    value = value.load(self._environ, key)
                return value if type is None else type(value)

        except Exception as e:
            last_error = e

        if default is MISSING:
            if last_error:
                raise last_error
            raise RuntimeError(f"Not found environment variable \"{self.envvar_prefix}{key}\" or config \"{key}\"")

        if isinstance(default, ConfigLoader):
            return default.load(self._environ, key)

        return default

    def walk(self, all: bool = False) -> Generator[Tuple[str, Any], None, None]:
        """
        遍历配置，默认不遍历内置配置
        """
        for key in self._config.keys():
            if all or key not in self._internal:
                yield key, self.get(key)

    def set(self, key: str, value: Any) -> None:
        """
        更新配置
        """
        self._config[key] = value

    def set_default(self, key: str, value: Any) -> Any:
        """
        设置默认配置
        """
        return self._config.setdefault(key, value)

    def update(self, **kwargs) -> None:
        """
        更新配置
        """
        self._config.update(**kwargs)

    def update_defaults(self, **kwargs) -> None:
        """
        更新默认配置
        """
        for key, value in kwargs.items():
            self._config.setdefault(key, value)

    def update_from_file(self, path: str, load: Callable[[IO[Any]], Mapping] = None) -> bool:
        """
        加载配置文件，按照扩展名来匹配相应的加载规则
        """
        if load is not None:
            return self._config.update_from_file(path, load=load)
        if path.endswith(".py"):
            return self._config.update_from_pyfile(path)
        elif path.endswith(".json"):
            return self._config.update_from_file(path, load=json.load)
        self._environ.logger.debug(f"Unsupported config file: {path}")
        return False

    def update_from_dir(self, path: str, recursion: bool = False) -> bool:
        """
        加载配置文件目录，按照扩展名来匹配相应的加载规则
        """
        # 路径不存在
        if not os.path.exists(path):
            return False
        # 如果不是目录
        if not os.path.isdir(path):
            return self.update_from_file(path)
        # 如果不需要递归，那只要取一级目录就好了
        if not recursion:
            for name in os.listdir(path):
                config_path = os.path.join(path, name)
                if not os.path.isdir(config_path):
                    self.update_from_file(config_path)
            return True
        # 剩下的就是需要递归读取所有文件的情况了
        for root, dirs, files in os.walk(path, topdown=False):
            for name in files:
                self.update_from_file(os.path.join(root, name))
        return True

    def update_from_envvar(self, prefix: str = None) -> bool:
        """
        加载所有以"{prefix}"为前缀的环境变量到配置中
        """
        if prefix is None:
            prefix = self.envvar_prefix
        for key, value in os.environ.items():
            if key.startswith(prefix):
                self._config[key[len(prefix):]] = value
        return True

    class Prompt(ConfigLoader):

        def __init__(
                self,
                prompt: str = None,
                password: bool = False,
                choices: Optional[List[str]] = None,
                default: Any = ...,
                type: Type = str,
                cached: bool = False,
                empty: bool = False,
        ):
            super().__init__()

            if issubclass(type, str):
                prompt_class = Prompt
            elif issubclass(type, int):
                prompt_class = IntPrompt
            elif issubclass(type, float):
                prompt_class = FloatPrompt
            else:
                raise NotImplementedError("prompt only supports str, int or float type")

            class ConfigPrompt(prompt_class):

                def process_response(self, value: str) -> PromptType:
                    value = value.strip()
                    if not empty and utils.is_empty(value):
                        raise InvalidResponse(self.validate_error_message)
                    return super().process_response(value)

            self.prompt_class = ConfigPrompt
            self.prompt = prompt
            self.password = password
            self.choices = choices
            self.default = default
            self.type = type
            self.cached = cached

        def _load(self, env: BaseEnviron, key: any):

            def process_default():
                if isinstance(self.default, ConfigLoader):
                    return self.default.load(env, key)
                return self.default

            def process_result(data):
                if self.type and not isinstance(data, self.type):
                    data = self.type(data)
                return data

            if not self.cached:
                return process_result(
                    self.prompt_class.ask(
                        self.prompt or f"Please input {key}",
                        password=self.password,
                        choices=self.choices,
                        default=process_default(),
                        show_default=True,
                        show_choices=True
                    )
                )

            default = MISSING
            path = env.get_data_path("configs", f"cached_{env.name}", str(key), create_parent=True)
            if os.path.exists(path):
                try:
                    default = process_result(utils.read_file(path, binary=False))
                    if not env.get_config("RELOAD_CONFIG", type=utils.bool):
                        return default
                except Exception as e:
                    env.logger.debug(f"Load cached config \"key\" error: {e}")

            result = process_result(
                self.prompt_class.ask(
                    self.prompt or f"Please input {key}",
                    password=self.password,
                    choices=self.choices,
                    default=process_default() if default is MISSING else default,
                    show_default=True,
                    show_choices=True
                )
            )

            utils.write_file(path, str(result))

            return result

    class Confirm(ConfigLoader):

        def __init__(
                self,
                prompt: str = None,
                default: Any = ...,
                cached: bool = False,
        ):
            super().__init__()
            self.prompt_class = Confirm
            self.prompt = prompt
            self.default = default
            self.cached = cached

        def _load(self, env: BaseEnviron, key: any):

            def process_default():
                if isinstance(self.default, ConfigLoader):
                    return self.default.load(env, key)
                return self.default

            def process_result(data):
                if not isinstance(data, bool):
                    data = utils.bool(data)
                return data

            if not self.cached:
                return process_result(
                    self.prompt_class.ask(
                        self.prompt or f"Please input {key}",
                        default=process_default(),
                        show_default=True,
                    )
                )

            default = MISSING
            path = env.get_data_path("configs", f"cached_{env.name}", str(key), create_parent=True)
            if os.path.exists(path):
                try:
                    default = process_result(utils.read_file(path, binary=False))
                    if not env.get_config("RELOAD_CONFIG", type=utils.bool):
                        return default
                except Exception as e:
                    env.logger.debug(f"Load cached config \"key\" error: {e}")

            result = process_result(
                self.prompt_class.ask(
                    self.prompt or f"Please confirm {key}",
                    default=process_default() if default is MISSING else default,
                    show_default=True,
                )
            )

            utils.write_file(path, str(result))

            return result

    class Lazy(ConfigLoader):

        def __init__(self, func: Callable[[BaseEnviron], Any]):
            super().__init__()
            self.func = func

        def _load(self, env: BaseEnviron, key: Any):
            return self.func(env)

    class Error(ConfigLoader):

        def __init__(self, message: str = None):
            super().__init__()
            self.message = message

        def _load(self, env: BaseEnviron, key: Any):
            raise RuntimeError(
                self.message or
                f"Please set \"{env.config.envvar_prefix}{key}\" as an environment variable, "
                f"or set \"{key}\" in config file"
            )
