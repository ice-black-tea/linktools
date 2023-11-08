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
import argparse
import functools
import inspect
import logging
import os
import sys
import textwrap
import traceback
from argparse import ArgumentParser, Action, Namespace, RawDescriptionHelpFormatter, SUPPRESS
from importlib.util import module_from_spec
from pkgutil import walk_packages
from typing import Tuple, Type, Optional, List, Generator, IO, Any, Callable, Iterable, Union, Set, Dict

import rich
from rich import get_console
from rich.prompt import IntPrompt
from rich.table import Table

from .argparse import BooleanOptionalAction
from .._environ import BaseEnviron, environ
from .._logging import LogHandler
from ..decorator import cached_property
from ..utils import ignore_error, read_file, write_file, T, MISSING


class CommandError(Exception):
    pass


class LogCommandMinix:

    def add_log_arguments(self: "BaseCommand", parser: ArgumentParser = None):

        environ = self.environ
        parser = parser or self._argument_parser

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

        parser = parser or self._argument_parser
        cache_path = self.environ.get_temp_path("cache", "device", "mobile", create_parent=True)

        def parse_handler(fn):
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                device = fn(*args, **kwargs)
                if device is not None:
                    write_file(cache_path, device.id)
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
                        device_id = read_file(cache_path, binary=False).strip()
                        if device_id:
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


_subcommand_index: int = 0
_subcommand_mapping: Dict[str, Set[str]] = {}


class _SubCommandInfo:

    def __init__(self):
        global _subcommand_index
        _subcommand_index += 1
        self.index = _subcommand_index
        self.name: Optional[str] = None
        self.help: Optional[str] = None
        self.func: Optional[Callable[..., Optional[int]]] = None
        self.arguments: List[_SubCommandArgumentInfo] = []

    def __repr__(self):
        return f"<SubCommandInfo name={self.name}>"


class _SubCommandArgumentInfo:

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.action: Optional[Union[str, Type[Action]]] = kwargs.get("action")


def subcommand(name=None, help=None):
    def decorator(func):
        if not hasattr(func, "__subcommand_info__"):
            setattr(func, "__subcommand_info__", _SubCommandInfo())

        subcommand_info: _SubCommandInfo = func.__subcommand_info__
        subcommand_info.name = name or func.__name__
        subcommand_info.help = help
        subcommand_info.func = func

        function = inspect.stack()[1].function
        _subcommand_mapping.setdefault(function, set())
        _subcommand_mapping[function].add(func.__name__)

        return func

    return decorator


def subcommand_argument(
        *name_or_flags: str,
        action: Union[str, Type[Action]] = MISSING,
        choices: Iterable[T] = MISSING,
        const: Any = MISSING,
        default: Any = MISSING,
        dest: str = MISSING,
        help: str = MISSING,
        metavar: Union[str, tuple[str, ...]] = MISSING,
        nargs: Union[int, str] = MISSING,
        required: bool = MISSING,
        type: Union[Type[Union[int, float]], Callable[[str], T], argparse.FileType] = MISSING,
        **kwargs: Any):
    def decorator(func):
        if not hasattr(func, "__subcommand_info__"):
            setattr(func, "__subcommand_info__", _SubCommandInfo())

        subcommand_info: _SubCommandInfo = func.__subcommand_info__
        subcommand_info.func = func
        subcommand_info.arguments.append(_SubCommandArgumentInfo(
            *name_or_flags,
            action=action,
            nargs=nargs,
            const=const,
            default=default,
            type=type,
            choices=choices,
            required=required,
            help=help,
            metavar=metavar,
            dest=dest,
            **kwargs
        ))

        return func

    return decorator


class SubCommandMixin:

    def add_subcommands(self: "BaseCommand", parser: ArgumentParser = None, target: Any = None) -> None:

        parser = parser or self._argument_parser
        target = target or self

        class_set = set()
        class_queue = list()

        class_queue.append(target.__class__)
        class_set.add(target.__class__)

        command_info_map: Dict[str, List[_SubCommandInfo]] = {}
        while class_queue:
            clazz = class_queue.pop(0)
            for pending_class in clazz.__bases__:
                if pending_class not in class_set:
                    class_queue.append(pending_class)
                    class_set.add(pending_class)
            if clazz.__name__ not in _subcommand_mapping:
                continue
            for func_name in _subcommand_mapping[clazz.__name__]:
                if not hasattr(clazz, func_name):
                    continue
                func = getattr(clazz, func_name)
                if not hasattr(func, "__subcommand_info__"):
                    continue
                command_info: _SubCommandInfo = func.__subcommand_info__
                command_info_map.setdefault(command_info.name, list())
                command_info_map[command_info.name].append(command_info)

        command_infos: List[Tuple[int, _SubCommandInfo]] = []
        for name, _command_infos in command_info_map.items():
            command_infos.append((min([i.index for i in _command_infos]), _command_infos[0]))

        subparsers = parser.add_subparsers(help="Commands", required=True)
        for order, command_info in sorted(command_infos, key=lambda o: o[0]):
            command_func = getattr(target, command_info.func.__name__)
            command_parser = subparsers.add_parser(command_info.name, help=command_info.help)
            command_parser.set_defaults(__subcommand_func__=command_func)
            command_parser.set_defaults(__subcommand_info__=command_info)

            for argument in command_info.arguments:
                argument_args = argument.args
                argument_kwargs = {k: v for k, v in argument.kwargs.items() if v is not MISSING}

                dest = argument_kwargs.get("dest", None)
                if not dest:
                    prefix_chars = command_parser.prefix_chars
                    if not argument_args or len(argument_args) == 1 and argument_args[0][0] not in prefix_chars:
                        dest = argument_args[0]
                        argument_kwargs["required"] = MISSING
                    else:
                        option_strings = []
                        long_option_strings = []
                        for option_string in argument_args:
                            option_strings.append(option_string)
                            if len(option_string) > 1 and option_string[1] in prefix_chars:
                                long_option_strings.append(option_string)
                        dest_option_string = long_option_strings[0] if long_option_strings else option_strings[0]
                        dest = dest_option_string.lstrip(prefix_chars)
                        if not dest:
                            raise ValueError(f"Parse subcommand argument dest error, "
                                             f"{command_info} argument `{', '.join(argument_args)}` require dest=...")
                        dest = dest.replace('-', '_')
                        argument_kwargs["dest"] = dest

                signature = inspect.signature(command_func)
                if dest not in signature.parameters:
                    raise ValueError(f"Check subcommand argument error, "
                                     f"{command_info} has no `{argument.action.dest}` argument")

                parameter = signature.parameters[dest]
                if "default" not in argument_kwargs:
                    if parameter.default != signature.empty:
                        argument_kwargs.setdefault("default", parameter.default)
                        argument_kwargs.setdefault("required", False)
                    else:
                        argument_kwargs.setdefault("required", True)
                if "action" not in argument_kwargs:
                    if parameter.annotation != signature.empty:
                        if parameter.annotation == bool:
                            if argument_kwargs.get("default", False):
                                argument_kwargs.setdefault("action", "store_false")
                            else:
                                argument_kwargs.setdefault("action", "store_true")
                        else:
                            argument_kwargs.setdefault("type", parameter.annotation)

                argument.action = command_parser.add_argument(
                    *argument_args,
                    **{k: v for k, v in argument_kwargs.items() if v is not MISSING}
                )

    def run_subcommand(self: "BaseCommand", args: Namespace) -> Optional[int]:
        command_info: _SubCommandInfo = args.__subcommand_info__
        command_func = args.__subcommand_func__
        kwargs = dict()
        for argument in command_info.arguments:
            kwargs[argument.action.dest] = getattr(args, argument.action.dest)
        return command_func(**kwargs)


class BaseCommand(SubCommandMixin, metaclass=abc.ABCMeta):

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
        pass

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

        LogCommandMinix.add_log_arguments(self)

        if self.environ.version != NotImplemented:
            self._argument_parser.add_argument(
                "--version", action="version", version=self.environ.version
            )

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
