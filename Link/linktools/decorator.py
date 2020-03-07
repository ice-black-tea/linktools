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
import threading


def singleton(cls):
    instances = {}

    def wrapper(*args, **kwargs):
        if cls not in instances:
            instances[cls] = cls(*args, **kwargs)
        return instances[cls]

    return wrapper


def try_except(errors=(Exception, ), default=None):

    def decorator(fn):
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
    def __init__(self, f):
        self._fname = f.__name__
        self._f = f

    def __get__(self, obj, owner):
        assert obj is not None, 'call {} on an instance'.format(self._fname)
        ret = obj.__dict__[self._fname] = self._f(obj)
        return ret
