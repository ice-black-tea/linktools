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

__all__ = (
    "TimeoutMeter", "Reactor", "ignore_error",
    "get_derived_type", "lazy_load", "lazy_raise",
    "popen", "exec",
    "int", "bool", "is_contain", "is_empty",
    "get_item", "pop_item", "get_list_item",
    "get_md5", "get_sha1", "get_sha256", "make_uuid", "gzip_compress",
    "read_file", "write_file", "get_lan_ip", "get_wan_ip"
)

import functools
import threading
import time
import traceback
from collections import deque
from collections.abc import Iterable
from typing import Union, Sized, Callable, Optional, Type, Any, List, TypeVar

from ._logging import get_logger
from ._proxy import get_derived_type, lazy_load, lazy_raise
from ._subprocess import popen, exec

_logger = get_logger("utils")


class TimeoutMeter:

    def __init__(self, timeout: Union[float, None]):
        self._deadline = None
        self._timeout = timeout
        self.reset()

    def reset(self) -> None:
        if self._timeout is not None and self._timeout >= 0:
            self._deadline = time.time() + self._timeout

    def get(self) -> Union[float, None]:
        timeout = None
        if self._deadline is not None:
            timeout = max(self._deadline - time.time(), 0)
        return timeout

    def check(self) -> "bool":
        if self._deadline is not None:
            if time.time() > self._deadline:
                return False
        return True


_T = TypeVar('_T')


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
    import hashlib
    if type(data) == str:
        data = bytes(data, 'utf8')
    m = hashlib.md5()
    m.update(data)
    return m.hexdigest()


def get_sha1(data: Union[str, bytes]) -> str:
    import hashlib
    if type(data) == str:
        data = bytes(data, 'utf8')
    s1 = hashlib.sha1()
    s1.update(data)
    return s1.hexdigest()


def get_sha256(data: Union[str, bytes]) -> str:
    import hashlib
    if type(data) == str:
        data = bytes(data, 'utf8')
    s1 = hashlib.sha256()
    s1.update(data)
    return s1.hexdigest()


def make_uuid() -> str:
    import uuid
    import random
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{uuid.uuid1()}{random.random()}")).replace("-", "")


def gzip_compress(data: Union[str, bytes]) -> bytes:
    import gzip
    if type(data) == str:
        data = bytes(data, 'utf8')
    return gzip.compress(data)


def read_file(path: str, binary: "bool" = True) -> Union[str, bytes]:
    with open(path, 'rb' if binary else 'r') as f:
        return f.read()


def write_file(path: str, data: [str, bytes]) -> None:
    with open(path, 'wb' if isinstance(data, bytes) else 'w') as f:
        f.write(data)


def get_lan_ip() -> Optional[str]:
    import socket
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        return s.getsockname()[0]
    except:
        return None
    finally:
        s.close()


def get_wan_ip() -> Optional[str]:
    from .urlutils import UrlFile
    with UrlFile(url="http://ifconfig.me/ip") as file:
        try:
            with open(file.save(), "rt") as fd:
                return fd.read().strip()
        except:
            return None
        finally:
            file.clear()


class Reactor(object):
    """
    Code stolen from frida_tools.application.Reactor
    """

    def __init__(self, on_stop=None, on_error=None):
        self._running = False
        self._on_stop = on_stop
        self._on_error = on_error
        self._pending = deque([])
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._worker = None

    def is_running(self) -> "bool":
        with self._lock:
            return self._running

    def run(self):
        with self._lock:
            self._running = True
        self._worker = threading.Thread(target=self._run)
        self._worker.setDaemon(True)
        self._worker.start()

    def _run(self):
        running = True
        while running:
            now = time.time()
            work = None
            timeout = None
            with self._lock:
                for item in self._pending:
                    (f, when) = item
                    if now >= when:
                        work = f
                        self._pending.remove(item)
                        break
                if len(self._pending) > 0:
                    timeout = max([min(map(lambda item: item[1], self._pending)) - now, 0])
                previous_pending_length = len(self._pending)

            if work is not None:
                try:
                    work()
                except (KeyboardInterrupt, EOFError) as e:
                    if self._on_error is not None:
                        self._on_error(e, traceback.format_exc())
                    self.stop()
                except BaseException as e:
                    if self._on_error is not None:
                        self._on_error(e, traceback.format_exc())

            with self._lock:
                if self._running and len(self._pending) == previous_pending_length:
                    self._cond.wait(timeout)
                running = self._running

        if self._on_stop is not None:
            self._on_stop()

    def stop(self, delay: float = None):
        self.schedule(self._stop, delay)

    def _stop(self):
        with self._lock:
            self._running = False

    def schedule(self, fn: Callable[[], any], delay: float = None):
        now = time.time()
        if delay is not None:
            when = now + delay
        else:
            when = now
        with self._lock:
            self._pending.append((functools.partial(self._work, fn), when))
            self._cond.notify()

    def _work(self, fn: Callable[[], any]):
        fn()

    def wait(self, timeout=5):
        assert self._worker
        self._worker.join(timeout)
        if self._worker.is_alive():
            _logger.warning("Worker did not finish normally")

    def __enter__(self):
        self.run()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        self.wait()


class InterruptableEvent(threading.Event):
    """
    解决 Windows 上 event.wait 不支持 ctrl+c 中断的问题
    """

    def wait(self, timeout=None):
        interval = 1
        wait = super().wait
        meter = TimeoutMeter(timeout)
        while True:
            t = meter.get()
            if t is None:
                t = interval
            elif t <= 0:
                break
            if wait(min(t, interval)):
                break
