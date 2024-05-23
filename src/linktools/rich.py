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
   /  oooooooooooooooo  .o.  oooo /,   `,"-----------
  / ==ooooooooooooooo==.o.  ooo= //   ,``--{)B     ,"
 /_==__==========__==_ooo__ooo=_/'   /___________,"
"""

import logging
import os
from datetime import datetime
from typing import TYPE_CHECKING, Optional, Union, List, Dict, Type, TypeVar, TextIO, Iterable

import rich
from rich.console import ConsoleRenderable, Console
from rich.logging import RichHandler
from rich.progress import Task, Progress, \
    ProgressColumn, TextColumn, BarColumn, DownloadColumn, \
    TransferSpeedColumn, TaskProgressColumn, TimeRemainingColumn
from rich.prompt import Prompt, IntPrompt, InvalidResponse, FloatPrompt, Confirm, PromptBase
from rich.table import Column
from rich.text import Text, TextType

from .metadata import __missing__

if TYPE_CHECKING:
    from ._environ import BaseEnviron


def is_terminal() -> bool:
    return rich.get_console().is_terminal


class LogHandler(RichHandler):

    def __init__(self, environ: "BaseEnviron"):
        super().__init__(
            show_path=False,
            show_level=environ.get_config("SHOW_LOG_LEVEL", type=bool),
            show_time=environ.get_config("SHOW_LOG_TIME", type=bool),
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
        if not style:
            style = "log.time"
        if not format:
            if self.formatter:
                format = self.formatter.datefmt
            if not format:
                format = "[%x %X]"
        return Text(time.strftime(format), style=style)

    def make_level_text(self, level_no: int, level_name: str = None, style: str = None) -> Text:
        if not level_name:
            level_name = logging.getLevelName(level_no)
        if not style:
            style = self.get_level_style(level_no)
            if not style:
                style = "log.level"
        return Text(f" {level_name[:1].upper()} ", style=style)

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
    def get_instance(cls) -> "Optional[LogHandler]":
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


class _LogColumn(ProgressColumn):

    def __init__(self):
        super().__init__(table_column=Column(no_wrap=True))

    def render(self, task: Task = None) -> Union[str, Text]:
        result = Text()

        handler = LogHandler.get_instance()
        if handler and handler.show_time:
            if len(result) > 0:
                result.append(" ")
            result.append(handler.make_time_text())

        if handler and handler.show_level:
            if len(result) > 0:
                result.append(" ")
            result.append(handler.make_level_text(logging.INFO))

        return result


def create_simple_progress(*fields: str):
    columns = []

    handler = LogHandler.get_instance()
    if handler and (handler.show_time or handler.show_level):
        columns.append(_LogColumn())

    columns.extend([
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
    ])

    for field in fields:
        columns.append(TextColumn(f"{{task.fields[{field}]}}"))

    return Progress(*columns)


def create_progress():
    columns = []

    handler = LogHandler.get_instance()
    if handler and (handler.show_time or handler.show_level):
        columns.append(_LogColumn())

    columns.extend([
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        DownloadColumn(),
        TransferSpeedColumn(),
        TaskProgressColumn(),
        TextColumn("eta"),
        TimeRemainingColumn(),
    ])

    return Progress(*columns)


if TYPE_CHECKING:
    PromptType = TypeVar("PromptType", bound=PromptBase)
    PromptResultType = TypeVar("PromptResultType", str, int, float, bool)

_prompt_types: "Dict[Type[PromptResultType], Type[PromptType]]" = {
    str: Prompt,
    int: IntPrompt,
    float: FloatPrompt,
    bool: Confirm,
}


def _create_prompt_class(type: "Type[PromptResultType]", allow_empty: bool) -> "Type[PromptType]":
    prompt_type = _prompt_types.get(type, None)
    if prompt_type is None:
        raise TypeError(f"Unknown prompt type: {prompt_type}")

    class RichPrompt(prompt_type):

        @classmethod
        def get_input(
                cls,
                console: Console,
                prompt: TextType,
                password: bool,
                stream: Optional[TextIO] = None,
        ) -> str:

            prefix = []
            prefix_len = 0

            handler = LogHandler.get_instance()
            if handler and handler.show_time:
                time = handler.make_time_text()
                prefix.append(time)
                prefix_len += time.cell_len + 1
            if handler and handler.show_level:
                level = handler.make_level_text(logging.WARNING, "↳")
                prefix.append(level)
                prefix_len += level.cell_len + 1

            lines = prompt.split(include_separator=True, allow_blank=True)
            console.print(*(*prefix, lines[0]), sep=" ", end="")
            for i in range(1, len(lines)):
                lines[i].pad_left(prefix_len)
                console.print(lines[i], new_line_start=True, end="")

            return console.input(password=password, stream=stream)

        def on_validate_error(self, value: str, error: InvalidResponse) -> None:
            prefix = Text("")
            handler = LogHandler.get_instance()
            if handler and handler.show_time:
                prefix = prefix + handler.make_time_text() + " "
            if handler and handler.show_level:
                prefix = prefix + handler.make_level_text(logging.ERROR, "↳") + " "
            self.console.print(prefix, error, sep="")

        def process_response(self, value: str) -> "PromptType":
            value = value.strip()
            if not allow_empty and not value:
                raise InvalidResponse(self.validate_error_message)
            return super().process_response(value)

    return RichPrompt


def prompt(
        prompt: str,
        type: "Type[PromptResultType]" = str,
        default: "PromptResultType" = __missing__,
        allow_empty: bool = False,
        choices: Optional[List[str]] = None,
        password: bool = False,
        show_default: bool = True,
        show_choices: bool = True
) -> "PromptResultType":
    return _create_prompt_class(type, allow_empty=allow_empty).ask(
        prompt,
        password=password,
        choices=choices,
        default=default if default != __missing__ else ...,
        show_default=show_default,
        show_choices=show_choices
    )


def choose(
        prompt: str,
        choices: Iterable[str],
        title: str = None,
        default: Union[int, str] = __missing__,
        show_default: bool = True,
        show_choices: bool = True
) -> int:
    choices = tuple(choices)

    if isinstance(default, str):
        default = choices.index(default) \
            if default in choices \
            else __missing__
    index = default \
        if default != __missing__ and 0 <= default < len(choices) \
        else 0

    begin = 1
    text = Text()
    if title:
        text.append(f"{title}{os.linesep}")
    for i in range(len(choices)):
        text.append(f"{'>> ' if i == index else '   '}")
        text.append(f"{f'{i + begin}:':2} ", "prompt.choices")
        text.append(f"{choices[i]}{os.linesep}")
    text.append(prompt)
    if show_choices:
        text.append(" ")
        text.append(f"[{begin}~{len(choices) + begin - 1}]" if len(choices) > 1 else f"[{begin}]", "prompt.choices")

    return _create_prompt_class(int, allow_empty=False).ask(
        text,
        choices=[str(i) for i in range(begin, len(choices) + begin, 1)],
        default=default + begin if default != __missing__ else ...,
        show_default=show_default,
        show_choices=False,
    ) - begin


def confirm(
        prompt: str,
        default: "PromptResultType" = __missing__,
        show_default: bool = True,
) -> bool:
    return _create_prompt_class(bool, allow_empty=False).ask(
        prompt,
        default=default if default != __missing__ else ...,
        show_default=show_default,
    )
