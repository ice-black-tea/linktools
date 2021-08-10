#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : logger.py 
@time    : 2020/03/22
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

# !/usr/bin/env python3
# -*- coding:utf-8 -*-
import functools
import logging

from .version import __name__

MESSAGE = 0x7fffffff
ERROR = logging.ERROR
WARNING = logging.WARNING
INFO = logging.INFO
DEBUG = logging.DEBUG


@functools.lru_cache(1)
def _import_modules():
    manager = logging.Manager(logging.getLogger())
    manager.setLoggerClass(_Logger)
    _logging = manager.getLogger(__name__)
    _logging.level = logging.DEBUG
    _handler = logging.StreamHandler()
    _handler.formatter = logging.Formatter('%(message)s')
    _logging.handlers.append(_handler)

    import colorama
    colorama.init(True)

    return _logging, colorama


class _Logger(logging.Logger):

    def _log(self, level, msg, args, **kwargs):
        msg, kwargs = self._compatible_args(*args, **kwargs)
        return super()._log(level, msg, None, **kwargs)

    @classmethod
    def _compatible_args(cls, *args, traceback_error=False, stack=False, options=None, **kwargs):
        if traceback_error:
            if "exc_info" not in kwargs:
                kwargs["exc_info"] = True
        if stack:
            if "stack_info" not in kwargs:
                kwargs["stack_info"] = True

        def get_option(item, default=None):
            if item in kwargs:
                return kwargs.pop(item)
            if options is not None:
                return options.get(item, default)
            return None

        msg = ""

        indent = get_option("indent", 0)
        if indent > 0:
            msg = msg + indent * " "
        fore = get_option("fore")
        if fore is not None:
            msg = msg + fore
        back = get_option("back")
        if back is not None:
            msg = msg + back
        style = get_option("style")
        if style is not None:
            msg = msg + style
        tag = get_option("tag", "")
        if len(tag) > 0:
            msg = msg + str(tag)
        for arg in args:
            msg = msg + str(arg)

        if indent + len(tag) > 0:
            import os
            msg = msg.replace(os.linesep, os.linesep + " " * (indent + len(tag)))

        return msg, kwargs


def set_level(level):
    logging, colorama = _import_modules()
    logging.setLevel(level)


def debug(*args, **kwargs):
    logging, colorama = _import_modules()
    logging.debug(None, *args, **kwargs,
                  options={
                      "fore": colorama.Fore.GREEN,
                      "back": colorama.Back.RESET,
                      "style": colorama.Style.NORMAL
                  })


def info(*args, **kwargs):
    logging, colorama = _import_modules()
    logging.info(None, *args, **kwargs,
                 options={
                     "fore": colorama.Fore.RESET,
                     "back": colorama.Back.RESET,
                     "style": colorama.Style.NORMAL
                 })


def warning(*args, **kwargs):
    logging, colorama = _import_modules()
    logging.warning(None, *args, **kwargs,
                    options={
                        "fore": colorama.Fore.MAGENTA,
                        "back": colorama.Back.RESET,
                        "style": colorama.Style.NORMAL
                    })


def error(*args, **kwargs):
    logging, colorama = _import_modules()
    logging.error(None, *args, **kwargs,
                  options={
                      "fore": colorama.Fore.RED,
                      "back": colorama.Back.RESET,
                      "style": colorama.Style.NORMAL
                  })


def message(*args, **kwargs):
    logging, colorama = _import_modules()
    logging.log(MESSAGE, None, *args, **kwargs,
                options={
                    "fore": colorama.Fore.RESET,
                    "back": colorama.Back.RESET,
                    "style": colorama.Style.NORMAL
                })
