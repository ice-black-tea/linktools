#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : decorator.py
@time    : 2019/01/15
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
import threading
from types import GenericAlias
from typing import Tuple, Type, Any, TypeVar, Callable

_T = TypeVar('_T')


def singleton(cls: Type[_T]) -> Callable[..., _T]:
    instances = {}

    @functools.wraps(cls)
    def wrapper(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]

    return wrapper


def try_except(errors: Tuple[Type[BaseException]] = (Exception,), default: Any = None):
    def decorator(fn: Callable[..., _T]) -> Callable[..., _T]:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs) -> _T:
            try:
                return fn(*args, **kwargs)
            except errors:
                return default

        return wrapper

    return decorator


def synchronized(lock=None):
    if lock is None:
        lock = threading.Lock()

    def decorator(fn: Callable[..., _T]) -> Callable[..., _T]:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs) -> _T:
            lock.acquire()
            try:
                return fn(*args, **kwargs)
            finally:
                lock.release()

        return wrapper

    return decorator


class cached_property:
    __missing__ = object()

    def __init__(self, func):
        self.func = func
        self.attrname = None
        self.__doc__ = func.__doc__
        self.lock = None

    def __set_name__(self, owner, name):
        if self.attrname is None:
            self.attrname = name
        elif name != self.attrname:
            raise TypeError(
                "Cannot assign the same cached_property to two different names "
                f"({self.attrname!r} and {name!r})."
            )

    def __get__(self, instance, owner=None):
        if instance is None:
            return self
        if self.attrname is None:
            raise TypeError(
                "Cannot use cached_property instance without calling __set_name__ on it.")
        try:
            cache = instance.__dict__
        except AttributeError:  # not all objects have __dict__ (e.g. class defines slots)
            msg = (
                f"No '__dict__' attribute on {type(instance).__name__!r} "
                f"instance to cache {self.attrname!r} property."
            )
            raise TypeError(msg) from None
        val = cache.get(self.attrname, self.__missing__)
        if val is self.__missing__:
            try:
                if self.lock:
                    self.lock.acquire()

                # check if another thread filled cache while we awaited lock
                val = cache.get(self.attrname, self.__missing__)
                if val is self.__missing__:
                    val = self.func(instance)
                    try:
                        cache[self.attrname] = val
                    except TypeError:
                        msg = (
                            f"The '__dict__' attribute on {type(instance).__name__!r} instance "
                            f"does not support item assignment for caching {self.attrname!r} property."
                        )
                        raise TypeError(msg) from None

            finally:
                if self.lock:
                    self.lock.release()

        return val

    __class_getitem__ = classmethod(GenericAlias)


class locked_cached_property(cached_property):

    def __init__(self, func, name=None, doc=None):
        super().__init__(func)
        self.lock = threading.RLock()
