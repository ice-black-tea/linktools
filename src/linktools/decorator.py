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
import logging
import threading
import traceback
from typing import Tuple, Type, Any, TypeVar, Callable

from ._logging import get_logger, LogHandler
from ._environ import environ

_logger = get_logger("decorator")
_T = TypeVar('_T')


def entry_point(
        show_log_time: bool = False,
        show_log_level: bool = True,
        known_errors: Tuple[Type[BaseException]] = (),
):
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                environ.show_log_time = show_log_time
                environ.show_log_level = show_log_level
                logging.basicConfig(
                    level=logging.INFO,
                    format="%(message)s",
                    datefmt="[%X]",
                    handlers=[LogHandler()]
                )
                code = fn(*args, **kwargs) or 0
            except SystemExit:
                raise
            except (KeyboardInterrupt, *known_errors) as e:
                error_type, error_message = e.__class__.__name__, str(e).strip()
                _logger.error(f"{error_type}: {error_message}" if error_message else error_type)
                code = 1
            except:
                _logger.error(traceback.format_exc())
                code = 1
            exit(code)

        return wrapper

    return decorator


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


# noinspection PyPep8Naming
class cached_property(object):
    _missing = object()

    def __init__(self, func, name=None, doc=None):
        self.__name__ = name or func.__name__
        self.__module__ = func.__module__
        self.__doc__ = doc or func.__doc__
        self.func = func

    def __get__(self, obj, owner):
        if obj is None:
            return self
        value = obj.__dict__.get(self.__name__, cached_property._missing)
        if value is cached_property._missing:
            value = self.func(obj)
            obj.__dict__[self.__name__] = value
        return value


# noinspection PyPep8Naming
class locked_cached_property(object):
    _missing = object()

    def __init__(self, func, name=None, doc=None):
        self.__name__ = name or func.__name__
        self.__module__ = func.__module__
        self.__doc__ = doc or func.__doc__
        self.func = func
        self.lock = threading.RLock()

    def __get__(self, obj, type=None):
        if obj is None:
            return self
        with self.lock:
            value = obj.__dict__.get(self.__name__, locked_cached_property._missing)
            if value is locked_cached_property._missing:
                value = self.func(obj)
                obj.__dict__[self.__name__] = value
            return value
