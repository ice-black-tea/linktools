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

MESSAGE = 0x00001000

logging.addLevelName(MESSAGE, "message")


def get_logger(name: str = None):
    manager = logging.Manager(logging.getLogger())
    manager.setLoggerClass(Logger)
    return manager.getLogger(name)


class Logger(logging.Logger):

    def debug(self, *args, **kwargs):
        super().debug(None, *args, **kwargs,
                      options={
                          "fore": colorama.Fore.GREEN,
                          "back": None,
                          "style": None
                      })

    def info(self, *args, **kwargs):
        super().info(None, *args, **kwargs,
                     options={
                         "fore": None,
                         "back": None,
                         "style": None
                     })

    def warning(self, *args, **kwargs):
        super().warning(None, *args, **kwargs,
                        options={
                            "fore": colorama.Fore.MAGENTA,
                            "back": None,
                            "style": None
                        })

    def error(self, *args, **kwargs):
        super().error(None, *args, **kwargs,
                      options={
                          "fore": colorama.Fore.RED,
                          "back": None,
                          "style": None
                      })

    def message(self, *args, **kwargs):
        super().log(MESSAGE, None, *args, **kwargs,
                    options={
                        "fore": None,
                        "back": None,
                        "style": None
                    })

    # noinspection PyTypeChecker, PyProtectedMember
    def _log(self, level, msg, args, **kwargs):
        msg, kwargs = self._compatible_args(args, **kwargs)
        return super()._log(level, msg, None, **kwargs)

    @classmethod
    def _compatible_args(cls, args, traceback_error=False, stack=False, options=None, **kwargs):
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
        tag = get_option("tag") or ""
        if len(tag) > 0:
            tag = str(tag) + " "
            msg = msg + tag
        for arg in args:
            msg = msg + str(arg)

        if indent + len(tag) > 0:
            msg = msg.replace(os.linesep, os.linesep + " " * (indent + len(tag)))

        if fore is not None and fore != colorama.Fore.RESET:
            msg = msg + colorama.Fore.RESET
        if back is not None and back != colorama.Back.RESET:
            msg = msg + colorama.Back.RESET
        if style is not None and style != colorama.Style.RESET_ALL:
            msg = msg + colorama.Style.RESET_ALL

        return msg, kwargs
