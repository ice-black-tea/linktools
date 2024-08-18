#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : utils.py
@time    : 2018/11/25
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
import functools
import getpass
import gzip
import hashlib
import os
import platform
import random
import re
import shutil
import socket
import sys
import uuid
from collections.abc import Iterable, Sized
from importlib.machinery import ModuleSpec
from importlib.util import find_spec, LazyLoader, module_from_spec, spec_from_file_location
from pathlib import Path
from typing import TYPE_CHECKING, Union, Callable, Optional, Type, Any, List, TypeVar, Tuple, Set, Dict, overload
from urllib import parse
from urllib.request import urlopen

from .._environ import environ
from ..decorator import singleton
from ..metadata import __missing__
from ..references.fake_useragent import UserAgent
from ..types import PathType, QueryType, Proxy, IterProxy

if TYPE_CHECKING:
    from typing import ParamSpec, Literal

    T = TypeVar("T")
    P = ParamSpec("P")

DEFAULT_ENCODING = "utf-8"
SYSTEM = platform.system().lower()
MACHINE = platform.machine().lower()


def ignore_error(
        fn: "Callable[P, T]", *,
        args: "P.args" = None, kwargs: "P.kwargs" = None,
        default: "T" = None) -> "T":
    try:
        if args is None:
            args = tuple()
        if kwargs is None:
            kwargs = dict()
        return fn(*args, **kwargs)
    except:
        return default


# noinspection PyShadowingBuiltins
def cast(type: "Type[T]", obj: Any, default: Any = __missing__) -> "Optional[T]":
    """
    类型转换
    :param type: 目标类型
    :param obj: 对象
    :param default: 默认值
    :return: 转换后的值
    """
    if default == __missing__:
        return type(obj)
    try:
        return type(obj)
    except:
        return default


def cast_int(obj: Any, default: Any = __missing__) -> int:
    """
    转为int
    :param obj: 需要转换的值
    :param default: 默认值
    :return: 转换后的值
    """
    return cast(int, obj, default)


def cast_bool(obj: Any, default: Any = __missing__) -> bool:
    """
    转为bool
    :param obj: 需要转换的值
    :param default: 默认值
    :return: 转换后的值
    """
    return cast(bool, obj, default)


def coalesce(*args: Any) -> Any:
    """
    从参数列表中返回第一个不为None的值
    """
    for arg in args:
        if arg is not None:
            return arg
    return None


def is_contain(obj: Any, key: Any) -> bool:
    """
    是否包含内容
    :param obj: 对象
    :param key: 键
    :return: 是否包含
    """
    if obj is None:
        return False
    if isinstance(obj, Iterable):
        return key in obj
    return False


def is_empty(obj: Any) -> bool:
    """
    对象是否为空
    :param obj: 对象
    :return: 是否为空
    """
    if obj is None:
        return True
    if isinstance(obj, Sized):
        return len(obj) == 0
    return False


# 1noinspection PyShadowingBuiltins, PyUnresolvedReferences
def get_item(obj: Any, *keys: Any, type: "Type[T]" = None, default: "T" = None) -> "Optional[T]":
    """
    获取子项
    :param obj: 对象
    :param keys: 键
    :param type: 对应类型
    :param default: 默认值
    :return: 子项
    """
    for key in keys:
        if obj is None:
            return default

        try:
            obj = obj[key]
            continue
        except:
            pass

        try:
            obj = getattr(obj, key)
            continue
        except:
            pass

        return default

    if obj is not None and type is not None:
        try:
            obj = type(obj)
        except:
            return default

    return obj


# 1noinspection PyShadowingBuiltins, PyUnresolvedReferences
def pop_item(obj: Any, *keys: Any, type: "Type[T]" = None, default: "T" = None) -> "Optional[T]":
    """
    获取并删除子项
    :param obj: 对象
    :param keys: 键
    :param type: 对应类型
    :param default: 默认值
    :return: 子项
    """
    last_obj = None
    last_key = None

    for key in keys:

        if obj is None:
            return default

        last_obj = obj
        last_key = key

        try:
            obj = obj[key]
            continue
        except:
            pass

        try:
            obj = getattr(obj, key)
            continue
        except:
            pass

        return default

    if last_obj is not None and last_key is not None:
        try:
            del last_obj[last_key]
        except:
            pass

    if obj is not None and type is not None:
        try:
            obj = type(obj)
        except:
            return default

    return obj


# 1noinspection PyShadowingBuiltins, PyUnresolvedReferences
def get_list_item(obj: Any, *keys: Any, type: "Type[T]" = None, default: "List[T]" = None) -> "Optional[List[T]]":
    """
    获取子项（列表）
    :param obj: 对象
    :param keys: 键
    :param type: 对应类型
    :param default: 默认值
    :return: 子项
    """
    objs = get_item(obj, *keys, default=None)
    if objs is None or not isinstance(objs, (Tuple, List, Set)):
        return default
    result = []
    for obj in objs:
        if obj is not None and type is not None:
            try:
                result.append(type(obj))
            except:
                pass
        else:
            result.append(obj)
    return result


def get_md5(data: Union[str, bytes]) -> str:
    if isinstance(data, str):
        data = bytes(data, "utf8")
    m = hashlib.md5()
    m.update(data)
    return m.hexdigest()


def get_sha1(data: Union[str, bytes]) -> str:
    if isinstance(data, str):
        data = bytes(data, "utf8")
    s1 = hashlib.sha1()
    s1.update(data)
    return s1.hexdigest()


def get_sha256(data: Union[str, bytes]) -> str:
    if isinstance(data, str):
        data = bytes(data, "utf8")
    s1 = hashlib.sha256()
    s1.update(data)
    return s1.hexdigest()


def make_uuid() -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{uuid.uuid1()}{random.random()}")).replace("-", "")


def gzip_compress(data: Union[str, bytes]) -> bytes:
    if isinstance(data, str):
        data = bytes(data, "utf8")
    return gzip.compress(data)


def get_path(root_path: PathType, *paths: [str], create_parent: bool = False) -> Path:
    target_path = Path(root_path)
    for path in paths:
        parent_path = target_path
        target_path = parent_path.joinpath(path)
        try:
            target_path.relative_to(parent_path)
        except ValueError:
            raise Exception(f"Unsafe path \"{path}\"")
    if create_parent:
        target_path.parent.mkdir(parents=True, exist_ok=True)
    return target_path


@overload
def read_file(path: "PathType") -> bytes: ...


@overload
def read_file(path: "PathType", text: "Literal[False]") -> bytes: ...


@overload
def read_file(path: "PathType", text: "Literal[True]", encoding=DEFAULT_ENCODING) -> str: ...


@overload
def read_file(path: "PathType", text: bool, encoding=DEFAULT_ENCODING) -> Union[str, bytes]: ...


def read_file(path: "PathType", text: bool = False, encoding=DEFAULT_ENCODING) -> Union[str, bytes]:
    """
    读取文件数据
    """
    if text:
        with open(path, "rt", encoding=encoding) as fd:
            return fd.read()
    else:
        with open(path, "rb") as fd:
            return fd.read()


def write_file(path: "PathType", data: [str, bytes], encoding=DEFAULT_ENCODING) -> None:
    """
    写入文件数据
    """
    if isinstance(data, str):
        with open(path, "wt", encoding=encoding) as fd:
            fd.write(data)
    else:
        with open(path, "wb") as fd:
            fd.write(data)


def remove_file(path: "PathType") -> None:
    """
    删除文件/目录
    """
    if not os.path.exists(path):
        return
    if os.path.isdir(path):
        shutil.rmtree(path, ignore_errors=True)
    else:
        ignore_error(os.remove, args=(path,))


def clear_directory(path: "PathType") -> None:
    """
    删除子目录
    """
    if not os.path.isdir(path):
        return
    for name in os.listdir(path):
        target_path = os.path.join(path, name)
        if os.path.isdir(target_path):
            shutil.rmtree(target_path, ignore_errors=True)
        else:
            ignore_error(os.remove, args=(target_path,))


def get_lan_ip() -> Optional[str]:
    """
    获取本地IP地址
    """
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except:
        return None
    finally:
        if s is not None:
            ignore_error(s.close)


def get_wan_ip() -> Optional[str]:
    """
    获取外网IP地址
    """
    try:
        with urlopen("http://ifconfig.me/ip") as response:
            return response.read().decode().strip()
    except:
        return None


def parse_version(version: str) -> Tuple[int, ...]:
    """
    将字符串版本号解析成元组
    """
    result = []
    for x in version.split("."):
        if x.isdigit():
            result.append(cast_int(x))
        else:
            match = re.match(r"^\d+", x)
            if not match:
                break
            result.append(cast_int(match.group(0)))
    return tuple(result)


_widths = [
    (126, 1), (159, 0), (687, 1), (710, 0), (711, 1),
    (727, 0), (733, 1), (879, 0), (1154, 1), (1161, 0),
    (4347, 1), (4447, 2), (7467, 1), (7521, 0), (8369, 1),
    (8426, 0), (9000, 1), (9002, 2), (11021, 1), (12350, 2),
    (12351, 1), (12438, 2), (12442, 0), (19893, 2), (19967, 1),
    (55203, 2), (63743, 1), (64106, 2), (65039, 1), (65059, 0),
    (65131, 2), (65279, 1), (65376, 2), (65500, 1), (65510, 2),
    (120831, 1), (262141, 2), (1114109, 1),
]


def get_char_width(char):
    """
    获取字符宽度
    """
    global _widths
    o = ord(char)
    if o == 0xe or o == 0xf:
        return 0
    for num, wid in _widths:
        if o <= num:
            return wid
    return 1


@singleton
class _UserAgent(UserAgent):

    def __init__(self):
        super().__init__(
            path=environ.get_asset_path(f"browsers.json"),
            fallback=environ.get_config("DEFAULT_USER_AGENT", type=str),
        )


def user_agent(style=None) -> str:
    """
    随机获取一个User-Agent
    """
    ua = _UserAgent()

    try:
        if style:
            return ua[style]

        return ua.random

    except Exception as e:
        environ.logger.debug(f"fetch user agent error: {e}")

    return ua.fallback


def make_url(url: str, *paths: str, **kwargs: "QueryType") -> str:
    """
    拼接URL
    """
    result = url

    for path in paths:
        result = result.rstrip("/") + "/" + path.lstrip("/")

    if len(kwargs) > 0:
        queries = []
        for key, value in kwargs.items():
            if isinstance(value, (list, tuple)):
                queries.extend((key, v) for v in value)
            else:
                queries.append((key, value))

        result = result + "?" + parse.urlencode(queries)

    return result


def guess_file_name(url: str) -> str:
    """
    根据url推测文件名
    """
    if not url:
        return ""
    try:
        return os.path.split(parse.urlparse(url).path)[1]
    except:
        return ""


def _parseparam(s):
    while s[:1] == ';':
        s = s[1:]
        end = s.find(';')
        while end > 0 and (s.count('"', 0, end) - s.count('\\"', 0, end)) % 2:
            end = s.find(';', end + 1)
        if end < 0:
            end = len(s)
        f = s[:end]
        yield f.strip()
        s = s[end:]


def parse_header(line):
    """Parse a Content-type like header.

    Return the main content-type and a dictionary of options.

    """
    parts = _parseparam(';' + line)
    key = parts.__next__()
    pdict = {}
    for p in parts:
        i = p.find('=')
        if i >= 0:
            name = p[:i].strip().lower()
            value = p[i + 1:].strip()
            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1]
                value = value.replace('\\\\', '\\').replace('\\"', '"')
            pdict[name] = value
    return key, pdict


def parser_cookie(cookie: str) -> Dict[str, str]:
    """
    解析cookie成字典
    """
    cookies = {}
    for item in cookie.split(";"):
        key_value = item.split("=", 1)
        cookies[key_value[0].strip()] = key_value[1].strip() if len(key_value) > 1 else ''
    return cookies


def get_system():
    """
    获取系统类型
    """
    return SYSTEM


def get_machine():
    """
    获取机器类型
    """
    return MACHINE


if SYSTEM in ("darwin", "linux"):

    import pwd


    def get_user(uid: int = None):
        """
        获取用户名，如果没有指定uid则返回当前用户名
        """
        return pwd.getpwuid(int(uid)) \
            if uid is not None \
            else getpass.getuser()


    def get_uid(user: str = None):
        """
        获取用户ID，如果没有指定用户则返回当前用户ID
        """
        return pwd.getpwnam(str(user)).pw_uid \
            if user is not None \
            else os.getuid()


    def get_gid(user: str = None):
        """
        获取用户组ID，如果没有指定用户则返回当前用户组ID
        """
        return pwd.getpwnam(str(user)).pw_gid \
            if user is not None \
            else os.getgid()


    def get_shell_path():
        """
        获取当前用户shell路径
        """
        if "SHELL" in os.environ:
            shell_path = os.environ["SHELL"]
            if shell_path and os.path.exists(shell_path):
                return shell_path
        try:
            return pwd.getpwnam(get_user()).pw_shell
        except:
            return shutil.which("zsh") or shutil.which("bash") or shutil.which("sh")

elif SYSTEM in ("windows",):

    def get_user(uid: int = None):
        """
        获取当前用户，windows固定为当前用户名
        """
        return getpass.getuser()


    def get_uid(user: str = None):
        """
        获取用户ID，windows固定为0
        """
        return 0


    def get_gid(user: str = None):
        """
        获取用户组ID，windows固定为0
        """
        return 0


    def get_shell_path():
        """
        获取当前用户shell路径
        """
        shell_path = shutil.which("powershell") or shutil.which("cmd")
        if shell_path:
            return shell_path
        if "ComSpec" in os.environ:
            shell_path = os.environ["ComSpec"]
            if shell_path and os.path.exists(shell_path):
                return shell_path
        raise NotImplementedError(f"Unsupported system `{SYSTEM}`")

else:

    def get_user(uid: int = None):
        """
        获取用户名，如果没有指定uid则返回当前用户名，windows固定为当前用户名
        """
        raise NotImplementedError(f"Unsupported system `{SYSTEM}`")


    def get_uid(user: str = None):
        """
        获取用户ID，如果没有指定用户则返回当前用户ID，windows固定为0
        """
        raise NotImplementedError(f"Unsupported system `{SYSTEM}`")


    def get_gid(user: str = None):
        """
        获取用户组ID，如果没有指定用户则返回当前用户组ID，windows固定为0
        """
        raise NotImplementedError(f"Unsupported system `{SYSTEM}`")


    def get_shell_path():
        """
        获取当前用户shell路径
        """
        raise NotImplementedError(f"Unsupported system `{SYSTEM}`")


def import_module(name: str, spec: ModuleSpec = None) -> "T":
    """
    延迟导入模块
    :param name: 模块名
    :param spec: 模块spec
    :return: module
    """
    if name in sys.modules:
        return sys.modules[name]
    spec = spec or find_spec(name)
    if not spec:
        raise ModuleNotFoundError(f"No module named '{name}'")
    loader = LazyLoader(spec.loader)
    spec.loader = loader
    module = module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


def import_module_file(name: str, path: str) -> "T":
    """
    延迟导入模块
    :param name: 模块名
    :param path: 模块路径
    :return: module
    """
    if name in sys.modules:
        return sys.modules[name]
    if os.path.isdir(path):
        path = os.path.join(path, "__init__.py")
    if not os.path.exists(path):
        raise ModuleNotFoundError(f"No such file or directory: '{path}'")
    spec = spec_from_file_location(name, path)
    if not spec:
        raise ModuleNotFoundError(f"No module named '{name}'")
    loader = LazyLoader(spec.loader)
    spec.loader = loader
    module = module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


def get_derived_type(t: "Type[T]") -> "Type[T]":
    """
    生成委托类型，常用于自定义类继承委托类，替换某些方法, 如：

    import subprocess

    class Popen(get_derived_type(subprocess.Popen)):
        __super__: subprocess.Popen

        def communicate(self, *args, **kwargs):
            out, err = self.__super__.communicate(*args, **kwargs)
            return 'fake out!!!', 'fake error!!!'

    process = Popen(subprocess.Popen(["/usr/bin/git", "status"]))
    print(process.communicate())  # ('fake out!!!', 'fake error!!!')

    :param t: 需要委托的类型
    :return: 同参数t，需要委托的类型
    """

    class Derived(Proxy):

        def __init__(self, obj: "T"):
            super().__init__()
            object.__setattr__(self, "__super__", obj)

        def _get_current_object(self):
            return self.__super__

    return Derived


def lazy_load(fn: "Callable[P, T]", *args: "P.args", **kwargs: "P.kwargs") -> "T":
    """
    延迟加载
    :param fn: 延迟加载的方法
    :return: proxy
    """
    return Proxy(functools.partial(fn, *args, **kwargs))


def lazy_iter(fn: "Callable[P, Iterable[T]]", *args: "P.args", **kwargs: "P.kwargs") -> "Iterable[T]":
    """
    延迟迭代
    :param fn: 延迟迭代的方法
    :return: proxy
    """
    return IterProxy(fn, *args, **kwargs)


def raise_error(e: BaseException):
    raise e


def lazy_raise(e: BaseException) -> "T":
    return lazy_load(raise_error, e)
