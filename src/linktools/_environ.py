#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : environment.py
@time    : 2020/03/01
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
import pathlib
import pickle
import sys
import threading
from types import ModuleType
from typing import TypeVar, Type, Optional, Any, Dict, Generator, Tuple, Callable, IO, Mapping, Union, List, Sized

from rich.prompt import Prompt, IntPrompt, FloatPrompt

from . import utils, version
from .decorator import cached_property, cached_classproperty

T = TypeVar("T")
root_path = os.path.dirname(__file__)
asset_path = os.path.join(root_path, "assets")
cli_path = os.path.join(root_path, "cli")
missing = object()


class ConfigLoader(abc.ABC):
    __lock__ = threading.RLock()

    def __init__(self):
        self._data: Union[str, object] = missing

    def load(self, env: "BaseEnviron", key: Any) -> Optional[str]:
        if self._data is not missing:
            return self._data
        with self.__lock__:
            if self._data is missing:
                self._data = self._load(env, key)
        return self._data

    @abc.abstractmethod
    def _load(self, env: "BaseEnviron", key: Any):
        pass


class ConfigPrompt(ConfigLoader):

    def __init__(
            self,
            prompt: str = None,
            password: bool = False,
            choices: Optional[List[str]] = None,
            default: Any = None,
            type: Type = str,
            cached: bool = False,
            trim: bool = True,
    ):
        super().__init__()
        self.prompt = prompt
        self.password = password
        self.choices = choices
        self.default = default
        self.cached = cached
        self.type = type
        self.trim = trim

    def _load(self, env: "BaseEnviron", key: any):
        if issubclass(self.type, str):
            prompt = Prompt
        elif issubclass(self.type, int):
            prompt = IntPrompt
        elif issubclass(self.type, float):
            prompt = FloatPrompt
        else:
            raise NotImplementedError("prompt only supports str, int or float type")

        def process_default():
            if isinstance(self.default, ConfigLoader):
                return self.default.load(env, key)
            return self.default

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
                    default=process_default(),
                    show_default=True,
                    show_choices=True
                )
            )

        default = missing

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
                default=process_default() if default is missing else default,
                show_default=True,
                show_choices=True
            )
        )

        with open(path, "wt") as fd:
            fd.write(str(result))

        return result


class ConfigLazy(ConfigLoader):

    def __init__(self, func: Callable[["BaseEnviron"], Any]):
        super().__init__()
        self.func = func

    def _load(self, env: "BaseEnviron", key: Any):
        return self.func(env)


class ConfigError(ConfigLoader):

    def __init__(self, message: str = None):
        super().__init__()
        self.message = message

    def _load(self, env: "BaseEnviron", key: Any):
        raise RuntimeError(
            self.message or
            f"Please set \"{env.envvar_prefix}{key}\" as an environment variable, or set \"{key}\" in config file"
        )


class Config(dict):

    def from_pyfile(self, filename: str, silent: bool = False) -> bool:
        d = ModuleType("config")
        d.__file__ = filename
        d.prompt = ConfigPrompt
        d.lazy = ConfigLazy
        d.error = ConfigError
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

    def from_object(self, obj: Union[object, str]) -> None:
        for key in dir(obj):
            if key[0].isupper():
                self[key] = getattr(obj, key)

    def from_mapping(self, mapping: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> bool:
        mappings: Dict[str, Any] = {}
        if mapping is not None:
            mappings.update(mapping)
        mappings.update(kwargs)
        for key, value in mappings.items():
            if key[0].isupper():
                self[key] = value
        return True


class BaseEnviron(abc.ABC):

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """
        模块名
        """
        pass

    @property
    def version(self) -> str:
        """
        模块版本号
        """
        return NotImplemented

    @property
    def description(self) -> str:
        """
        模块描述
        """
        return NotImplemented

    @property
    def root_path(self):
        """
        模块路径
        """
        raise NotImplemented

    @cached_property
    def data_path(self):
        """
        存放文件目录
        """
        path = self.get_config("DATA_PATH", type=str, default=None)
        if not path:
            path = os.path.join(self.get_config("STORAGE_PATH", type=str), "data")
        return path

    @cached_property
    def temp_path(self):
        """
        存放临时文件目录
        """
        path = self.get_config("TEMP_PATH", type=str, default=None)
        if not path:
            path = os.path.join(self.get_config("STORAGE_PATH", type=str), "temp")
        return path

    @classmethod
    def _get_path(cls, root_path: str, *paths: [str], create: bool = False, create_parent: bool = False):
        target_path = parent_path = os.path.abspath(root_path)
        for path in paths:
            target_path = os.path.abspath(os.path.join(parent_path, path))
            common_path = os.path.commonpath([parent_path, target_path])
            if target_path == parent_path or parent_path != common_path:
                raise Exception(f"Unsafe path \"{path}\"")
            parent_path = target_path
        dir_path = None
        if create:
            dir_path = target_path
        elif create_parent:
            dir_path = os.path.dirname(target_path)
        if dir_path is not None:
            if not os.path.exists(dir_path):
                os.makedirs(dir_path)
        return target_path

    def get_path(self, *paths: str):
        """
        获取模块目录下的子路径
        """
        if self.root_path == NotImplemented:
            raise RuntimeError("root_path not implemented")
        return self._get_path(self.root_path, *paths)

    def get_data_path(self, *paths: str, create_parent: bool = False):
        """
        获取数据目录下的子路径
        """
        return self._get_path(self.data_path, *paths, create=False, create_parent=create_parent)

    def get_data_dir(self, *paths: str, create: bool = False):
        """
        获取数据目录下的子目录
        """
        return self._get_path(self.data_path, *paths, create=create, create_parent=False)

    def get_temp_path(self, *paths: str, create_parent: bool = False):
        """
        获取临时文件目录下的子路径
        """
        return self._get_path(self.temp_path, *paths, create=False, create_parent=create_parent)

    def get_temp_dir(self, *paths: str, create: bool = False):
        """
        获取临时文件目录下的子目录
        """
        return self._get_path(self.temp_path, *paths, create=create, create_parent=False)

    @cached_property
    def logger(self):
        """
        模块根logger
        """
        from ._logging import get_logger

        return get_logger(prefix=self.name)

    def get_logger(self, name: str = None):
        """
        获取模块名作为前缀的logger
        """
        from ._logging import get_logger

        return get_logger(name=name, prefix=self.name)

    @cached_classproperty
    def _internal_config(self) -> Config:
        config = Config()

        # 初始化内部配置
        config.update(
            DEBUG=False,
            STORAGE_PATH=str(pathlib.Path.home() / f".{version.__name__}"),
            ENVVAR_PREFIX=None,
            SHOW_LOG_TIME=False,
            SHOW_LOG_LEVEL=True,
        )

        if version.__release__:
            # 只有发布版本才会有这个文件
            config.from_file(
                self._get_path(asset_path, "tools.json"),
                json.load
            )
        else:
            try:
                # 不是发布版本的话，使用tools.yml配置代替
                import yaml
                config.from_file(
                    self._get_path(asset_path, "tools.yml"),
                    yaml.safe_load
                )
            except ModuleNotFoundError:
                raise ModuleNotFoundError(f"Please install pyyaml: {sys.executable} -m pip install pyyaml")

        return config

    @cached_property
    def _config(self) -> Config:
        config = pickle.loads(
            pickle.dumps(self._internal_config)
        )
        self._init_config(config)
        return config

    def _init_config(self, config: Config):
        config["ENVVAR_PREFIX"] = f"{self.name.upper()}_"

    def get_configs(self, namespace: str, lowercase: bool = True, trim_namespace: bool = True) -> Dict[str, Any]:
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
            rv[key] = self.get_config(k)
        return rv

    def get_config(self, key: str, type: Type[T] = None, empty: bool = False, default: T = missing) -> Optional[T]:
        """
        获取指定配置，优先会从环境变量中获取
        """

        def process_result(data):
            if not empty:  # 处理不允许为空，但配置为空的情况
                if data is None:
                    raise RuntimeError(f"Config \"{key}\" is None")
                elif isinstance(data, Sized) and len(data) == 0:
                    raise RuntimeError(f"Config \"{key}\" is empty")
            return data if type is None else type(data)

        env_key = f"{self.envvar_prefix}{key}"
        if env_key in os.environ:
            value = os.environ.get(env_key)
            return process_result(value)

        if key in self._config:
            value = self._config.get(key)
            if isinstance(value, ConfigLoader):
                value = value.load(self, key)
            return process_result(value)

        if default is missing:
            raise RuntimeError(f"Not found environment variable \"{self.envvar_prefix}{key}\" or config \"{key}\"")

        if isinstance(default, ConfigLoader):
            return default.load(self, key)

        return default

    def walk_configs(self, include_internal: bool = False) -> Generator[Tuple[str, Any], None, None]:
        """
        遍历配置
        """
        internal_config = self._internal_config
        for key in sorted(self._config.keys()):
            if include_internal or key not in internal_config:
                yield key, self.get_config(key)

    def update_configs(self, **kwargs) -> None:
        """
        更新配置
        """
        self._config.update(**kwargs)

    def set_config(self, key: str, value: Any) -> None:
        """
        更新配置
        """
        self._config[key] = value

    def update_config_from_file(self, path: str) -> bool:
        """
        加载配置文件，按照扩展名来匹配相应的加载规则
        """
        if path.endswith(".py"):
            return self._config.from_pyfile(path)
        elif path.endswith(".json"):
            return self._config.from_file(path, load=json.load)
        self.logger.debug(f"Unsupported config file: {path}")
        return False

    def update_config_from_dir(self, path: str, recursion: bool = False) -> bool:
        """
        加载配置文件目录，按照扩展名来匹配相应的加载规则
        """
        # 路径不存在
        if not os.path.exists(path):
            return False
        # 如果不是目录
        if not os.path.isdir(path):
            return self.update_config_from_file(path)
        # 如果不需要递归，那只要取一级目录就好了
        if not recursion:
            for name in os.listdir(path):
                config_path = os.path.join(path, name)
                if not os.path.isdir(config_path):
                    self.update_config_from_file(config_path)
            return True
        # 剩下的就是需要递归读取所有文件的情况了
        for root, dirs, files in os.walk(path, topdown=False):
            for name in files:
                self.update_config_from_file(os.path.join(root, name))
        return True

    def update_config_from_envvar(self) -> bool:
        """
        加载所有以"{name}_"为前缀的环境变量到配置中
        """
        prefix = self.envvar_prefix
        for key, value in os.environ.items():
            if key.startswith(prefix):
                self._config[key[len(prefix):]] = value
        return True

    @cached_property
    def tools(self):
        """
        工具集
        """
        from ._tools import ToolContainer

        tools = ToolContainer(self)

        # set environment variable
        index = 0
        dir_names = os.environ["PATH"].split(os.pathsep)
        for tool in tools:
            # dirname(executable[0]) -> environ["PATH"]
            if tool.executable:
                dir_name = tool.dirname
                if dir_name and dir_name not in dir_names:
                    # insert to head
                    dir_names.insert(index, tool.dirname)
                    index += 1
        # add all paths to environment variables
        os.environ["PATH"] = os.pathsep.join(dir_names)

        return tools

    def get_tool(self, name: str, **kwargs):
        """
        获取指定工具
        """
        tool = self.tools[name]
        if len(kwargs) != 0:
            tool = tool.copy(**kwargs)
        return tool

    @property
    def system(self) -> str:
        """
        系统名称
        """
        return self.tools.system

    @property
    def debug(self) -> bool:
        """
        debug模式
        """
        return self.get_config("DEBUG", type=utils.bool)

    @debug.setter
    def debug(self, value: bool):
        """
        debug模式
        """
        self.set_config("DEBUG", value)

    @property
    def envvar_prefix(self):
        """
        环境变量前缀，只看保存在config中的配置
        """
        return self._config.get("ENVVAR_PREFIX")

    @envvar_prefix.setter
    def envvar_prefix(self, value: str):
        """
        环境变量前缀，只看保存在config中的配置
        """
        return self.set_config("ENVVAR_PREFIX", value)

    @property
    def show_log_time(self) -> bool:
        """
        显示日志时间，只对使用LogHandler的logger有效
        """
        return self.get_config("SHOW_LOG_TIME", type=utils.bool)

    @show_log_time.setter
    def show_log_time(self, value: bool):
        """
        显示日志时间，只对使用LogHandler的logger有效
        """
        from ._logging import LogHandler

        handler = LogHandler.get_instance()
        if handler:
            handler.show_time = value
        self.set_config("SHOW_LOG_TIME", value)

    @property
    def show_log_level(self) -> bool:
        """
        显示日志级别，只对使用LogHandler的logger有效
        """
        return self.get_config("SHOW_LOG_LEVEL", type=utils.bool)

    @show_log_level.setter
    def show_log_level(self, value: bool):
        """
        显示日志级别，只对使用LogHandler的logger有效
        """
        from ._logging import LogHandler

        handler = LogHandler.get_instance()
        if handler:
            handler.show_level = value
        self.set_config("SHOW_LOG_LEVEL", value)


class Environ(BaseEnviron):
    name = version.__name__
    description = version.__description__
    version = version.__version__
    root_path = root_path

    def _init_config(self, config: Config):
        super()._init_config(config)

        # 初始化下载相关参数
        config["DOWNLOAD_USER_AGENT"] = \
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) " \
            "AppleWebKit/537.36 (KHTML, like Gecko) " \
            "Chrome/98.0.4758.109 " \
            "Safari/537.36"

        # 导入configs文件夹中所有配置文件
        config.from_file(
            self._get_path(asset_path, "android-tools.json"),
            load=json.load
        )

    def get_cli_path(self, *paths: str) -> str:
        return self._get_path(cli_path, *paths)

    def get_asset_path(self, *paths: str) -> str:
        return self._get_path(asset_path, *paths)


environ = Environ()
