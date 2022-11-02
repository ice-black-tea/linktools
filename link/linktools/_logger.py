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

__all__ = ("get_logger", "Handler")

import logging
import os

from rich.console import ConsoleRenderable
from rich.logging import RichHandler
from rich.text import Text

from .version import __name__ as module_name


class Handler(RichHandler):
    __default_styles = {
        logging.DEBUG: {
            "level": "black on blue",
            "message": None,
        },
        logging.INFO: {
            "level": "black on green",
            "message": None,
        },
        logging.WARNING: {
            "level": "black on yellow",
            "message": "magenta1",
        },
        logging.ERROR: {
            "level": "black on red1",
            "message": "red1",
        },
        logging.CRITICAL: {
            "level": "black on red1",
            "message": "red1",
        },
    }

    def __init__(self):
        super().__init__(
            show_path=False,
            # show_level=False,
            # show_time=False,
            omit_repeated_times=False,
            # markup=True,
            # highlighter=NullHighlighter()
        )

    def _get_level_style(self, level_no):
        style = self.__default_styles.get(level_no)
        if style:
            return style.get("level")
        return None

    def _get_message_style(self, level_no):
        style = self.__default_styles.get(level_no)
        if style:
            return style.get("message")
        return None

    def get_level_text(self, record: logging.LogRecord) -> Text:
        level_name = record.levelname
        level_no = record.levelno
        return Text(f" {level_name[:1]} ", style=self._get_level_style(level_no))

    def render_message(self, record: logging.LogRecord, message: str) -> "ConsoleRenderable":
        indent = getattr(record, "indent", 0)
        if indent > 0:
            message = " " * indent + message
            message = message.replace(os.linesep, os.linesep + " " * indent)

        use_markup = getattr(record, "markup", self.markup)
        style = getattr(record, "style", self._get_message_style(record.levelno))
        message_text = Text.from_markup(message, style=style) if use_markup else Text(message, style=style)

        highlighter = getattr(record, "highlighter", False)
        if highlighter and self.highlighter:
            message_text = self.highlighter(message_text)

        return message_text


class Logger(logging.Logger):

    # noinspection PyTypeChecker, PyProtectedMember
    def _log(self, level, msg, args, **kwargs):
        msg += ''.join([str(i) for i in args])

        extra = kwargs.get("extra") or {}
        self._move_args(kwargs, extra, "style")
        self._move_args(kwargs, extra, "indent")
        self._move_args(kwargs, extra, "markup")
        self._move_args(kwargs, extra, "highlighter")
        kwargs["extra"] = extra

        return super()._log(level, msg, None, **kwargs)

    @classmethod
    def _move_args(cls, from_, to_, key):
        value = from_.pop(key, None)
        if value is not None:
            to_[key] = value


manager = logging.Manager(logging.getLogger())
manager.setLoggerClass(Logger)


def get_logger(name: str = None, prefix=module_name) -> "Logger":
    if prefix:
        name = f"{prefix}.{name}" if name else prefix
    logger = manager.getLogger(name)
    return logger
