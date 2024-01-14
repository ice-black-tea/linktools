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
   /  oooooooooooooooo  .o.  oooo /,   \,"-----------
  / ==ooooooooooooooo==.o.  ooo= //   ,`\--{)B     ,"
 /_==__==========__==_ooo__ooo=_/'   /___________,"
"""
import functools
import gzip
import hashlib
import inspect
import os
import random
import re
import socket
import threading
import time
import uuid
from collections.abc import Iterable, Sized
from typing import TYPE_CHECKING, Union, Callable, Optional, Type, Any, List, TypeVar, Tuple, Set, Dict
from urllib.request import urlopen

from ..metadata import __missing__

T = TypeVar("T")


class Timeout:

    def __init__(self, timeout: Union[float, int] = None):
        self._deadline = None
        self._timeout = timeout
        self.reset()

    @property
    def remain(self) -> Union[float, None]:
        timeout = None
        if self._deadline is not None:
            timeout = max(self._deadline - time.time(), 0)
        return timeout

    @property
    def deadline(self) -> Union[float, None]:
        return self._deadline

    def reset(self) -> None:
        if self._timeout is not None and self._timeout >= 0:
            self._deadline = time.time() + self._timeout

    def check(self) -> bool:
        if self._deadline is not None:
            if time.time() > self._deadline:
                return False
        return True

    def ensure(self, err_type=TimeoutError, message=None) -> None:
        if not self.check():
            raise err_type(message)

    def __repr__(self):
        return f"Timeout(timeout={self._timeout})"


if TYPE_CHECKING:
    from typing import ParamSpec

    P = ParamSpec("P")


def timeoutable(fn: "Callable[P, T]") -> "Callable[P, T]":
    timeout_keyword = "timeout"

    timeout_index = -1
    positional_index = -1
    keyword_index = -1

    index = 0
    for key, parameter in inspect.signature(fn).parameters.items():
        if key == timeout_keyword:
            timeout_index = index
            break
        elif parameter.kind in (parameter.KEYWORD_ONLY, parameter.VAR_KEYWORD):
            keyword_index = index
        elif parameter.kind in (parameter.VAR_POSITIONAL,):
            positional_index = index
        index += 1

    if timeout_index < 0 and keyword_index < 0:
        raise RuntimeError(f"Not found timeout parameter in {fn}")

    if 0 <= positional_index < timeout_index:
        # 如果timeout在*args参数后面，那就只能通过**kwargs访问了
        timeout_index = -1

    @functools.wraps(fn)
    def wrapper(*args: "P.args", **kwargs: "P.kwargs") -> T:
        if 0 <= timeout_index < len(args):
            timeout = args[timeout_index]
            if isinstance(timeout, Timeout):
                pass
            elif isinstance(timeout, (float, int, type(None))):
                args = list(args)
                args[timeout_index] = Timeout(timeout)
            else:
                raise RuntimeError(f"Timeout/int/float was expects, got {type(timeout)}")
        elif timeout_keyword in kwargs:
            timeout = kwargs.get(timeout_keyword)
            if isinstance(timeout, Timeout):
                pass
            elif isinstance(timeout, (float, int, type(None))):
                kwargs[timeout_keyword] = Timeout(timeout)
            else:
                raise RuntimeError(f"Timeout/int/float was expects, got {type(timeout)}")
        else:
            kwargs[timeout_keyword] = Timeout()

        return fn(*args, **kwargs)

    return wrapper


class InterruptableEvent(threading.Event):
    """
    解决 Windows 上 event.wait 不支持 ctrl+c 中断的问题
    """

    @timeoutable
    def wait(self, timeout: Timeout = None):
        interval = 1
        wait = super().wait
        while True:
            t = timeout.remain
            if t is None:
                t = interval
            elif t <= 0:
                break
            if wait(min(t, interval)):
                break


def ignore_error(
        fn: Callable[..., T], *,
        args: Tuple[Any, ...] = None, kwargs: Dict[str, Any] = None,
        default: T = None) -> T:
    try:
        if args is None:
            args = tuple()
        if kwargs is None:
            kwargs = dict()
        return fn(*args, **kwargs)
    except:
        return default


# noinspection PyShadowingBuiltins
def cast(type: Type[T], obj: Any, default: Any = __missing__) -> Optional[T]:
    """
    类型转换
    :param type: 目标类型
    :param obj: 对象
    :param default: 默认值
    :return: 转换后的值
    """
    if default is __missing__:
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
def get_item(obj: Any, *keys: Any, type: Type[T] = None, default: T = None) -> Optional[T]:
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
def pop_item(obj: Any, *keys: Any, type: Type[T] = None, default: T = None) -> Optional[T]:
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
def get_list_item(obj: Any, *keys: Any, type: Type[T] = None, default: List[T] = None) -> Optional[List[T]]:
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


def get_path(root_path: str, *paths: [str], create: bool = False, create_parent: bool = False):
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
            os.makedirs(dir_path, exist_ok=True)
    return target_path


if TYPE_CHECKING:
    from typing import Literal, overload

    @overload
    def read_file(path: str) -> bytes: ...


    @overload
    def read_file(path: str, binary: Literal[True]) -> bytes: ...


    @overload
    def read_file(path: str, binary: Literal[False]) -> str: ...


    @overload
    def read_file(path: str, binary: bool) -> Union[str, bytes]: ...


def read_file(path: str, binary: bool = True) -> Union[str, bytes]:
    with open(path, "rb" if binary else "rt") as f:
        return f.read()


def write_file(path: str, data: [str, bytes]) -> None:
    with open(path, "wb" if isinstance(data, bytes) else "wt") as f:
        f.write(data)


def get_lan_ip() -> Optional[str]:
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
    try:
        with urlopen("http://ifconfig.me/ip") as response:
            return response.read().decode().strip()
    except:
        return None


def parse_version(version: str) -> Tuple[int, ...]:
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
    global _widths
    o = ord(char)
    if o == 0xe or o == 0xf:
        return 0
    for num, wid in _widths:
        if o <= num:
            return wid
    return 1
