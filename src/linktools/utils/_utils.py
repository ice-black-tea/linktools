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
import gzip
import hashlib
import random
import re
import socket
import threading
import time
import uuid
from collections.abc import Iterable, Sized
from typing import Union, Callable, Optional, Type, Any, List, TypeVar
from urllib.request import urlopen

_T = TypeVar("_T")


class Timeout:

    def __init__(self, timeout: Union[float, None]):
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
    def deadline(self):
        return self._deadline

    def reset(self) -> None:
        if self._timeout is not None and self._timeout >= 0:
            self._deadline = time.time() + self._timeout

    def check(self) -> "bool":
        if self._deadline is not None:
            if time.time() > self._deadline:
                return False
        return True

    def ensure(self) -> None:
        if not self.check():
            raise TimeoutError()

    def __repr__(self):
        return f"Timeout(timeout={self._timeout})"


class InterruptableEvent(threading.Event):
    """
    解决 Windows 上 event.wait 不支持 ctrl+c 中断的问题
    """

    def wait(self, timeout=None):
        interval = 1
        wait = super().wait
        timeout = Timeout(timeout)
        while True:
            t = timeout.remain
            if t is None:
                t = interval
            elif t <= 0:
                break
            if wait(min(t, interval)):
                break


def ignore_error(fn: Callable[..., _T], *args, **kwargs) -> _T:
    try:
        return fn(*args, **kwargs)
    except:
        return None


# noinspection PyShadowingBuiltins
def cast(type: type, obj: object, default=None):
    """
    类型转换
    :param type: 目标类型
    :param obj: 对象
    :param default: 默认值
    :return: 转换后的值
    """
    try:
        return type(obj)
    except:
        return default


def int(obj: object, default: int = 0) -> int:
    """
    转为int
    :param obj: 需要转换的值
    :param default: 默认值
    :return: 转换后的值
    """
    return cast(type(0), obj, default=default)


def bool(obj: object, default: bool = False) -> "bool":
    """
    转为bool
    :param obj: 需要转换的值
    :param default: 默认值
    :return: 转换后的值
    """
    return cast(type(True), obj, default=default)


def is_contain(obj: object, key: object) -> "bool":
    """
    是否包含内容
    :param obj: 对象
    :param key: 键
    :return: 是否包含
    """
    if object is None:
        return False
    if isinstance(obj, Iterable):
        return key in obj
    return False


def is_empty(obj: object) -> "bool":
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
def get_item(obj: Any, *keys: Any, type: Type[_T] = None, default: _T = None) -> Optional[_T]:
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
def pop_item(obj: Any, *keys: Any, type: Type[_T] = None, default: _T = None) -> Optional[_T]:
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
def get_list_item(obj: Any, *keys: Any, type: Type[_T] = None, default: List[_T] = None) -> List[Optional[_T]]:
    """
    获取子项（列表）
    :param obj: 对象
    :param keys: 键
    :param type: 对应类型
    :param default: 默认值
    :return: 子项
    """
    objs = get_item(obj, *keys, default=None)
    if objs is None or not isinstance(objs, Iterable):
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
    if type(data) == str:
        data = bytes(data, "utf8")
    m = hashlib.md5()
    m.update(data)
    return m.hexdigest()


def get_sha1(data: Union[str, bytes]) -> str:
    if type(data) == str:
        data = bytes(data, "utf8")
    s1 = hashlib.sha1()
    s1.update(data)
    return s1.hexdigest()


def get_sha256(data: Union[str, bytes]) -> str:
    if type(data) == str:
        data = bytes(data, "utf8")
    s1 = hashlib.sha256()
    s1.update(data)
    return s1.hexdigest()


def make_uuid() -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{uuid.uuid1()}{random.random()}")).replace("-", "")


def gzip_compress(data: Union[str, bytes]) -> bytes:
    if type(data) == str:
        data = bytes(data, "utf8")
    return gzip.compress(data)


def read_file(path: str, binary: "bool" = True) -> Union[str, bytes]:
    with open(path, "rb" if binary else 'r') as f:
        return f.read()


def write_file(path: str, data: [str, bytes]) -> None:
    with open(path, "wb" if isinstance(data, bytes) else "w") as f:
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


def parse_version(version: str) -> [int, ...]:
    result = []
    for x in version.split("."):
        if x.isdigit():
            result.append(int(x))
        else:
            match = re.match(r"^\d+", x)
            if not match:
                break
            result.append(int(match.group(0)))
    return tuple(result)


def range_type(min: int, max: int):
    def wrapper(o):
        value = int(o)
        if min <= value <= max:
            return value
        raise ValueError("value not in range %s-%s" % (min, max))

    return wrapper
