#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : entry.py 
@time    : 2022/12/18
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

import abc
import functools
import logging
import os
import sys
import textwrap
import traceback
from argparse import ArgumentParser, Action, Namespace, RawDescriptionHelpFormatter, SUPPRESS
from importlib.util import module_from_spec
from pkgutil import walk_packages
from typing import Tuple, Type, Optional, List, Generator, IO

import rich
from rich import get_console
from rich.prompt import IntPrompt
from rich.table import Table

from .argparse import BooleanOptionalAction
from .._environ import BaseEnviron, environ
from .._logging import LogHandler
from ..decorator import cached_property
from ..utils import ignore_error


class CommandError(Exception):
    pass


class LogCommandMinix:

    def add_log_arguments(self: "BaseCommand", parser: ArgumentParser):
        environ = self.environ

        class VerboseAction(Action):

            def __call__(self, parser, namespace, values, option_string=None):
                logging.root.setLevel(logging.DEBUG)

        class DebugAction(Action):

            def __call__(self, parser, namespace, values, option_string=None):
                environ.debug = True
                environ.logger.setLevel(logging.DEBUG)

        class LogTimeAction(BooleanOptionalAction):

            def __call__(self, parser, namespace, values, option_string=None):
                if option_string in self.option_strings:
                    value = not option_string.startswith("--no-")
                    handler = LogHandler.get_instance()
                    if handler:
                        handler.show_time = value
                    environ.set_config("SHOW_LOG_TIME", value)

        class LogLevelAction(BooleanOptionalAction):

            def __call__(self, parser, namespace, values, option_string=None):
                if option_string in self.option_strings:
                    value = not option_string.startswith("--no-")
                    handler = LogHandler.get_instance()
                    if handler:
                        handler.show_level = value
                    environ.set_config("SHOW_LOG_LEVEL", value)

        group = parser.add_argument_group(title="log arguments")
        group.add_argument("--verbose", action=VerboseAction, nargs=0, const=True, dest=SUPPRESS,
                           help="increase log verbosity")
        group.add_argument("--debug", action=DebugAction, nargs=0, const=True, dest=SUPPRESS,
                           help=f"increase {self.environ.name}'s log verbosity, and enable debug mode")

        if LogHandler.get_instance():
            group.add_argument("--time", action=LogTimeAction, dest=SUPPRESS,
                               help="show log time")
            group.add_argument("--level", action=LogLevelAction, dest=SUPPRESS,
                               help="show log level")


class DeviceCommandMixin:

    def add_device_arguments(self: "BaseCommand", parser: ArgumentParser):

        from ..device import Bridge, BridgeError

        cache_path = self.environ.get_temp_path("cache", "device", "mobile", create_parent=True)

        def parse_handler(fn):
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                device = fn(*args, **kwargs)
                if device is not None:
                    with open(cache_path, "wt+") as fd:
                        fd.write(device.id)
                return device

            return wrapper

        @parse_handler
        def parse_device():
            devices = tuple(Bridge.list_devices(alive=True))
            if len(devices) == 0:
                raise BridgeError("no devices/emulators found")

            if len(devices) == 1:
                return devices[0]

            table = Table(show_lines=True)
            table.add_column("Index", justify="right", style="cyan", no_wrap=True)
            table.add_column("ID", style="magenta")
            table.add_column("Name", style="magenta")

            offset = 1
            for i in range(len(devices)):
                table.add_row(
                    str(i + offset),
                    ignore_error(lambda: devices[i].id),
                    ignore_error(lambda: devices[i].name) or "",
                )

            console = get_console()
            console.print(table)

            prompt = f"More than one device/emulator. {os.linesep}" \
                     f"Enter device index"
            choices = [str(i) for i in range(offset, len(devices) + offset, 1)]
            index = IntPrompt.ask(prompt, choices=choices, default=offset, console=console)

            return devices[index - offset]

        class IDAction(Action):

            def __call__(self, parser, namespace, values, option_string=None):
                @parse_handler
                def wrapper():
                    device_id = str(values)
                    for device in Bridge.list_devices():
                        if device.id == device_id:
                            return device
                    raise BridgeError(f"no devices/emulators with {device_id} found")

                setattr(namespace, self.dest, wrapper)

        class LastAction(Action):

            def __call__(self, parser, namespace, values, option_string=None):
                @parse_handler
                def wrapper():
                    if os.path.exists(cache_path):
                        with open(cache_path, "rt") as fd:
                            device_id = fd.read().strip()
                        if len(device_id) > 0:
                            for device in Bridge.list_devices():
                                if device.id == device_id:
                                    return device
                    raise BridgeError("no device used last time")

                setattr(namespace, self.dest, wrapper)

        group = parser.add_argument_group(title="mobile device arguments").add_mutually_exclusive_group()
        group.add_argument("-i", "--id", metavar="ID", dest="parse_device", action=IDAction,
                           help="specify unique device identifier", default=parse_device)
        group.add_argument("-l", "--last", dest="parse_device", nargs=0, const=True, action=LastAction,
                           help="use last device")


class BaseCommand(metaclass=abc.ABCMeta):

    @property
    def name(self):
        return self.__module__

    @property
    def environ(self) -> BaseEnviron:
        return environ

    @property
    def logger(self) -> logging.Logger:
        return self.environ.logger

    @cached_property
    def description(self) -> str:
        return textwrap.dedent((self.__doc__ or "").strip())

    @property
    def known_errors(self) -> List[Type[BaseException]]:
        return [CommandError]

    @abc.abstractmethod
    def run(self, args: List[str]) -> Optional[int]:
        pass

    def print_help(self, file: IO[str] = None):
        return self._argument_parser.print_help(file=file)

    def parse_args(self, args: List[str]) -> Namespace:
        return self._argument_parser.parse_args(args=args)

    def parse_known_args(self, args: List[str]) -> Tuple[Namespace, List[str]]:
        return self._argument_parser.parse_known_args(args=args)

    @cached_property
    def _argument_parser(self) -> ArgumentParser:
        description = self.description.strip()
        if description and self.environ.description != NotImplemented:
            description += os.linesep + os.linesep
            description += self.environ.description

        parser = ArgumentParser(
            formatter_class=RawDescriptionHelpFormatter,
            description=description,
            conflict_handler="resolve"
        )
        self.init_base_arguments(parser)
        self.init_arguments(parser)

        return parser

    @abc.abstractmethod
    def init_arguments(self, parser: ArgumentParser) -> None:
        pass

    def init_base_arguments(self, parser: ArgumentParser) -> None:
        if self.environ.version != NotImplemented:
            parser.add_argument("--version", action="version", version=self.environ.version)

    def main(self, *args, **kwargs) -> None:
        if rich.get_console().is_terminal:
            logging.basicConfig(
                level=logging.INFO,
                format="%(message)s",
                datefmt="[%X]",
                handlers=[LogHandler()]
            )
        else:
            logging.basicConfig(
                level=logging.INFO,
                format="[%(asctime)s] %(levelname)s %(module)s %(funcName)s %(message)s",
                datefmt="%H:%M:%S"
            )

        LogCommandMinix.add_log_arguments(self, self._argument_parser)

        exit(self(*args, **kwargs))

    def __call__(self, args: [str] = None) -> int:
        try:
            args = args if args is not None else sys.argv[1:]
            exit_code = self.run(args) or 0

        except SystemExit as e:
            exit_code = e.code

        except (KeyboardInterrupt, EOFError, *self.known_errors) as e:
            exit_code = 1
            error_type, error_message = e.__class__.__name__, str(e).strip()
            self.logger.error(
                f"{error_type}: {error_message}" if error_message else error_type,
                exc_info=True if environ.debug else None,
            )

        except:
            exit_code = 1
            if environ.debug:
                console = get_console()
                console.print_exception(show_locals=True)
            else:
                self.logger.error(traceback.format_exc())

        return exit_code


def walk_commands(path: str) -> Generator["BaseCommand", None, None]:
    for finder, name, is_pkg in sorted(walk_packages(path=[path]), key=lambda i: i[1]):
        if is_pkg:
            continue
        try:
            spec = finder.find_spec(name)
            module = module_from_spec(spec)
            spec.loader.exec_module(module)
            command = getattr(module, "command", None)
            if command and isinstance(command, BaseCommand):
                yield command
        except Exception as e:
            environ.logger.warning(
                f"Ignore {name}, caused by {e.__class__.__name__}: {e}",
                exc_info=e if environ.debug else None
            )
