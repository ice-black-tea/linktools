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
import os

from .decorator import singleton, locked_cached_property


@singleton
class Logger:

    def __init__(self):
        import colorama
        colorama.init(True)

        logging.basicConfig(
            level=logging.DEBUG,
            format='%(message)s'
        )

    @locked_cached_property
    def colorama(cls):
        import colorama
        colorama.init(True)
        return colorama

    def debug(self, *args, **kwargs):
        msg, args, kwargs = self._compatible_args(
            args, kwargs,
            fore=self.colorama.Fore.GREEN, back=self.colorama.Back.RESET, style=self.colorama.Style.NORMAL
        )
        logging.debug(msg, *args, **kwargs)

    def info(self, *args, **kwargs):
        msg, args, kwargs = self._compatible_args(
            args, kwargs,
            fore=self.colorama.Fore.RESET, back=self.colorama.Back.RESET, style=self.colorama.Style.NORMAL
        )
        logging.info(msg, *args, **kwargs)

    def warning(self, *args, **kwargs):
        msg, args, kwargs = self._compatible_args(
            args, kwargs,
            fore=self.colorama.Fore.MAGENTA, back=self.colorama.Back.RESET, style=self.colorama.Style.NORMAL
        )
        logging.warning(msg, *args, **kwargs)

    def error(self, *args, **kwargs):
        msg, args, kwargs = self._compatible_args(
            args, kwargs,
            fore=self.colorama.Fore.RED, back=self.colorama.Back.RESET, style=self.colorama.Style.NORMAL
        )
        logging.error(msg, *args, **kwargs)

    @classmethod
    def _compatible_args(cls, args, kwargs, **options):
        if "traceback_error" in kwargs:
            del kwargs["traceback_error"]
            if "exc_info" not in kwargs:
                kwargs["exc_info"] = True
        if "stack" in kwargs:
            del kwargs["stack"]
            if "stack_info" not in kwargs:
                kwargs["stack_info"] = True

        def get_option(item, default=None):
            if item in kwargs:
                return kwargs.pop(item)
            return options.get(item, default)

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
            msg = msg.replace(os.linesep, os.linesep + " " * (indent + len(tag)))

        return msg, [], kwargs


logger = Logger()
