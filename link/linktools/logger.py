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
import logging

from . import utils
from .version import __name__

MESSAGE = 0x7fffffff
ERROR = logging.ERROR
WARNING = logging.WARNING
INFO = logging.INFO
DEBUG = logging.DEBUG


def _get_colorama():
    import platform
    import ctypes
    if "windows" in platform.system().lower():  # works for Win7, 8, 10 ...
        k = ctypes.windll.kernel32
        k.SetConsoleMode(k.GetStdHandle(-11), 7)

    import colorama
    colorama.init(autoreset=False)
    return colorama


def _get_logger():
    manager = logging.Manager(logging.getLogger())
    manager.setLoggerClass(_Logger)
    logger = manager.getLogger(__name__)
    logger.level = logging.DEBUG
    handler = logging.StreamHandler()
    handler.formatter = logging.Formatter('%(message)s')
    logger.handlers.append(handler)
    return logger


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

        if fore is not None and fore != _colorama.Fore.RESET:
            msg = msg + _colorama.Fore.RESET
        if back is not None and back != _colorama.Back.RESET:
            msg = msg + _colorama.Back.RESET
        if style is not None and style != _colorama.Style.RESET_ALL:
            msg = msg + _colorama.Style.RESET_ALL

        return msg, kwargs


_colorama = utils.lazy_load(_get_colorama)
_logger = utils.lazy_load(_get_logger)


def set_level(level):
    _logger.setLevel(level)


def get_level():
    return _logger.level


def debug(*args, **kwargs):
    _logger.debug(None, *args, **kwargs,
                  options={
                      "fore": _colorama.Fore.GREEN,
                      "back": None,
                      "style": None
                  })


def info(*args, **kwargs):
    _logger.info(None, *args, **kwargs,
                 options={
                     "fore": None,
                     "back": None,
                     "style": None
                 })


def warning(*args, **kwargs):
    _logger.warning(None, *args, **kwargs,
                    options={
                        "fore": _colorama.Fore.MAGENTA,
                        "back": None,
                        "style": None
                    })


def error(*args, **kwargs):
    _logger.error(None, *args, **kwargs,
                  options={
                      "fore": _colorama.Fore.RED,
                      "back": None,
                      "style": None
                  })


def message(*args, **kwargs):
    _logger.log(MESSAGE, None, *args, **kwargs,
                options={
                    "fore": None,
                    "back": None,
                    "style": None
                })
