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

__all__ = ("get_logger", "Logger")

import logging
import os

import colorama

from .version import __name__ as module_name


class Logger(logging.Logger):
    __options = {
        logging.DEBUG: {
            "fore": colorama.Fore.GREEN,
            "back": None,
            "style": None
        },
        logging.INFO: {
            "fore": None,
            "back": None,
            "style": None
        },
        logging.WARNING: {
            "fore": colorama.Fore.MAGENTA,
            "back": None,
            "style": None
        },
        logging.ERROR: {
            "fore": colorama.Fore.RED,
            "back": None,
            "style": None
        },
    }

    @classmethod
    def set_debug_options(cls, **kwargs):
        cls.__options.get(logging.DEBUG).update(kwargs)

    @classmethod
    def set_info_options(cls, **kwargs):
        cls.__options.get(logging.INFO).update(kwargs)

    @classmethod
    def set_warning_options(cls, **kwargs):
        cls.__options.get(logging.WARNING).update(kwargs)

    @classmethod
    def set_error_options(cls, **kwargs):
        cls.__options.get(logging.ERROR).update(kwargs)

    def debug(self, *args, **kwargs):
        super().debug(None, *args, **kwargs)

    def info(self, *args, **kwargs):
        super().info(None, *args, **kwargs)

    def warning(self, *args, **kwargs):
        super().warning(None, *args, **kwargs)

    def error(self, *args, **kwargs):
        super().error(None, *args, **kwargs)

    # noinspection PyTypeChecker, PyProtectedMember
    def _log(self, level, msg, args, **kwargs):
        options = self.__options.get(level)
        msg, kwargs = self._compatible_args(args, **kwargs, options=options)
        return super()._log(level, msg, None, **kwargs)

    @classmethod
    def _compatible_args(cls, args, options=None, **kwargs):

        def get_option(item, default=None):
            if item in kwargs:
                return kwargs.pop(item)
            if options is not None:
                return options.get(item, default)
            return None

        fore = get_option("fore")
        back = get_option("back")
        style = get_option("style")

        def set_styles():
            result = ""
            if fore is not None:
                result = result + fore
            if back is not None:
                result = result + back
            if style is not None:
                result = result + style
            return result

        def reset_styles():
            result = ""
            if fore is not None and fore != colorama.Fore.RESET:
                result = result + colorama.Fore.RESET
            if back is not None and back != colorama.Back.RESET:
                result = result + colorama.Back.RESET
            if style is not None and style != colorama.Style.RESET_ALL:
                result = result + colorama.Style.RESET_ALL
            return result

        msg = ""

        tag = get_option("tag") or ""
        if tag:
            tag = tag + " "
            msg += str(tag)

        indent = get_option("indent", 0)
        if indent > 0:
            msg = msg + indent * " "

        msg += set_styles()
        for arg in args:
            msg = msg + str(arg)
        if indent + len(tag) > 0:
            msg = msg.replace(os.linesep, os.linesep + " " * (indent + len(tag)))
        msg += reset_styles()

        return msg, kwargs


manager = logging.Manager(logging.getLogger())
manager.setLoggerClass(Logger)


def get_logger(name: str = None, prefix=module_name) -> "Logger":
    if prefix:
        name = f"{prefix}.{name}" if name else prefix
    return manager.getLogger(name)
