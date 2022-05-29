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
import traceback


def entry_point(logger_tag: bool = False, known_errors: [Exception] = ()):
    from linktools import logger

    if logger_tag:
        logger.set_debug_options(tag="[D]")
        logger.set_info_options(tag="[I]")
        logger.set_warning_options(tag="[W]")
        logger.set_error_options(tag="[E]")

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except (KeyboardInterrupt, EOFError, *known_errors) as e:
                etype = e.__class__.__name__
                error = f"{e}".strip()
                logger.error(f"{etype}: {error}" if error else etype)
            except Exception:
                logger.error(traceback.format_exc())

        return wrapper

    return decorator


def singleton(cls):
    instances = {}

    def wrapper(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]

    return wrapper


def try_except(errors=(Exception,), default=None):
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                return fn(*args, **kwargs)
            except errors:
                return default

        return wrapper

    return decorator


def synchronized(lock=None):
    if lock is None:
        lock = threading.Lock()

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
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
