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
import os
import sys
import traceback

import colorama
from colorama import Fore, Back, Style

from .decorator import singleton, cached_property


class LoggerArgs:

    def __init__(self, args, kwargs, default):
        self.args = args
        self.kwargs = kwargs
        self.default = default

    @cached_property
    def indent(self):
        return self.get("indent", default=0)

    @cached_property
    def tag(self):
        tag = str(self.get("tag", default=""))
        if len(tag) > 0 and not tag.endswith(" "):
            tag = tag + " "
        return tag

    @cached_property
    def fore(self):
        return self.get("fore")

    @cached_property
    def back(self):
        return self.get("back")

    @cached_property
    def style(self):
        return self.get("style")

    @cached_property
    def stack(self):
        DEFAULT_LIMIT = "undefined"
        stack = ""
        limit = self.get("traceback_limit", default=DEFAULT_LIMIT)
        if limit == DEFAULT_LIMIT:
            return stack
        for item in traceback.format_stack(sys._getframe(5), limit=limit):
            stack = stack + item
        return stack

    @cached_property
    def message(self):
        message = ""
        if self.indent > 0:
            message = message + self.indent * " "
        if self.fore is not None:
            message = message + self.fore
        if self.back is not None:
            message = message + self.back
        if self.style is not None:
            message = message + self.style
        if len(self.tag) > 0:
            message = message + self.tag
        for arg in self.args:
            message = message + str(arg)
        if len(self.stack) > 0:
            message = message + os.linesep + self.stack
        return message.replace(os.linesep, os.linesep + " " * (self.indent + len(self.tag)))

    def get(self, item, default=None):
        if item not in self.kwargs:
            if item in self.default:
                return self.default[item]
            return default
        value = self.kwargs[item]
        del self.kwargs[item]
        return value


@singleton
class Logger:
    DEBUG = 1
    INFO = 2
    WARNING = 3
    ERROR = 4

    def __init__(self):
        colorama.init(True)
        self.level = self.INFO

    def debug(self, *args, **kwargs):
        if self.level <= self.DEBUG:
            logger_args = LoggerArgs(args, kwargs, default={
                "fore": Fore.GREEN,
                "back": Back.RESET,
                "style": Style.NORMAL,
            })
            print(logger_args.message, **kwargs)

    def info(self, *args, **kwargs):
        if self.level <= self.INFO:
            logger_args = LoggerArgs(args, kwargs, default={
                "fore": Fore.RESET,
                "back": Back.RESET,
                "style": Style.NORMAL,
            })
            print(logger_args.message, **kwargs)

    def warning(self, *args, **kwargs):
        if self.level <= self.WARNING:
            logger_args = LoggerArgs(args, kwargs, default={
                "fore": Fore.MAGENTA,
                "back": Back.RESET,
                "style": Style.NORMAL,
            })
            print(logger_args.message, **kwargs)

    def error(self, *args, **kwargs):
        if self.level <= self.ERROR:
            logger_args = LoggerArgs(args, kwargs, default={
                "fore": Fore.RED,
                "back": Back.RESET,
                "style": Style.NORMAL,
            })
            print(logger_args.message, **kwargs)


logger = Logger()
