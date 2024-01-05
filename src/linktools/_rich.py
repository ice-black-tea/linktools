#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : logging.py
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

import logging
import os
from datetime import datetime
from typing import Optional, Union

from rich.console import ConsoleRenderable
from rich.logging import RichHandler
from rich.progress import Task, Progress, \
    ProgressColumn, TextColumn, BarColumn, DownloadColumn, \
    TransferSpeedColumn, TaskProgressColumn, TimeRemainingColumn
from rich.table import Column
from rich.text import Text

from ._environ import BaseEnviron


class LogHandler(RichHandler):

    def __init__(self, environ: BaseEnviron):
        super().__init__(
            show_path=False,
            show_level=environ.get_config("SHOW_LOG_LEVEL"),
            show_time=environ.get_config("SHOW_LOG_TIME"),
            omit_repeated_times=False,
            log_time_format=self.make_time_text
            # markup=True,
            # highlighter=NullHighlighter()
        )

        self._styles = {
            logging.DEBUG: {
                "level": "black on blue",
                "message": "deep_sky_blue1",
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

    @property
    def show_level(self):
        return self._log_render.show_level

    @show_level.setter
    def show_level(self, value: bool):
        self._log_render.show_level = value

    @property
    def show_time(self):
        return self._log_render.show_time

    @show_time.setter
    def show_time(self, value: bool):
        self._log_render.show_time = value

    def get_time_style(self, level_no):
        style = self._styles.get(level_no)
        if style:
            return style.get("time")
        return None

    def get_level_style(self, level_no):
        style = self._styles.get(level_no)
        if style:
            return style.get("level")
        return None

    def get_message_style(self, level_no):
        style = self._styles.get(level_no)
        if style:
            return style.get("message")
        return None

    def make_time_text(self, time: Union[float, datetime, None] = None, format: str = None, style: str = None) -> Text:
        if not time:
            time = datetime.now()
        elif isinstance(time, (int, float)):
            time = datetime.fromtimestamp(time)
        if not format:
            format = "[%x %X]"
        if not style:
            style = "log.time"
        return Text(time.strftime(format), style=style)

    def make_level_text(self, level_no: int, level_name: str = None, style: str = None) -> Text:
        if not level_name:
            level_name = logging.getLevelName(level_no)
        if not style:
            style = self.get_level_style(level_no)
            if not style:
                style = "log.level"
        return Text(f" {level_name[:1]} ", style=style)

    def get_level_text(self, record: logging.LogRecord) -> Text:
        level_name = record.levelname
        level_no = record.levelno
        return self.make_level_text(level_no, level_name)

    def render_message(self, record: logging.LogRecord, message: str) -> ConsoleRenderable:
        indent = getattr(record, "indent", 0)
        if indent > 0:
            message = " " * indent + message
            message = message.replace(os.linesep, os.linesep + " " * indent)

        use_markup = getattr(record, "markup", self.markup)
        style = getattr(record, "style", self.get_message_style(record.levelno))
        message_text = Text.from_markup(message, style=style) if use_markup else Text(message, style=style)

        highlighter = getattr(record, "highlighter", False)
        if highlighter and self.highlighter:
            message_text = self.highlighter(message_text)

        return message_text

    @classmethod
    def get_instance(cls) -> Optional["LogHandler"]:
        c = logging.getLogger()
        while c:
            if c.handlers:
                for handler in c.handlers:
                    if isinstance(handler, LogHandler):
                        return handler
            if not c.propagate:
                return None
            else:
                c = c.parent
        return None


class LogColumn(ProgressColumn):

    def render(self, task: Task = None) -> Union[str, Text]:
        handler = LogHandler.get_instance()
        if not handler:
            return ""
        result = Text()
        if handler.show_time:
            date_format = None
            if handler.formatter:
                date_format = handler.formatter.datefmt
            result.append(handler.make_time_text(format=date_format))
            result.append(" ")
        if handler.show_level:
            result.append(handler.make_level_text(logging.WARNING))
        return result


def create_progress():
    return Progress(
        LogColumn(table_column=Column(no_wrap=True)),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        DownloadColumn(),
        TransferSpeedColumn(),
        TaskProgressColumn(),
        TextColumn("eta"),
        TimeRemainingColumn(),
    )
