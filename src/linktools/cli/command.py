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
import inspect
import logging
import os
import sys
import textwrap
import traceback
from argparse import ArgumentParser, Action, Namespace, RawDescriptionHelpFormatter, SUPPRESS, FileType, HelpFormatter
from importlib.util import module_from_spec
from pkgutil import walk_packages
from typing import Tuple, Type, Optional, List, Generator, Any, Callable, Iterable, Union, Set, Dict

import rich
from rich import get_console

from .argparse import BooleanOptionalAction
from .._environ import BaseEnviron, environ
from .._logging import LogHandler
from ..decorator import cached_property
from ..utils import T, MISSING


class CommandError(Exception):
    pass


class LogCommandMixin:

    def add_log_options(self: "BaseCommand", parser: ArgumentParser = None):

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

        group = parser.add_argument_group(title="log options")
        group.add_argument("--verbose", action=VerboseAction, nargs=0, const=True, dest=SUPPRESS,
                           help="increase log verbosity")
        group.add_argument("--debug", action=DebugAction, nargs=0, const=True, dest=SUPPRESS,
                           help=f"increase {self.environ.name}'s log verbosity, and enable debug mode")

        if LogHandler.get_instance():
            group.add_argument("--time", action=LogTimeAction, dest=SUPPRESS,
                               help="show log time")
            group.add_argument("--level", action=LogLevelAction, dest=SUPPRESS,
                               help="show log level")


_subcommand_index: int = 0
_subcommand_mapping: Dict[str, Set[str]] = {}


class _SubCommandInfo:

    def __init__(self):
        global _subcommand_index
        _subcommand_index += 1
        self.index = _subcommand_index
        self.name: Optional[str] = None
        self.kwargs: Optional[Dict[str, Any]] = None
        self.func: Optional[Callable[..., Optional[int]]] = None
        self.arguments: List[_SubCommandArgumentInfo] = []

    def save(self, name: str, **kwargs: Any):
        self.name = name
        self.kwargs = _filter_kwargs(kwargs)
        return self

    def __repr__(self):
        return f"<SubCommandInfo name={self.name}>"


class _SubCommandArgumentInfo:

    def __init__(self):
        self.args: Optional[Tuple[str]] = None
        self.kwargs: Optional[Dict[str, Any]] = None
        self.action: Optional[Union[str, Type[Action]]] = None

    def save(self, *args: str, **kwargs: Any):
        self.args = args
        self.kwargs = _filter_kwargs(kwargs)
        return self


def _filter_kwargs(kwargs):
    return {k: v for k, v in kwargs.items() if v is not MISSING}


def subcommand(
        name: str,
        *,
        help: str = MISSING,
        aliases: List[str] = MISSING,
        prog: str | None = MISSING,
        usage: str | None = MISSING,
        description: str | None = MISSING,
        epilog: str | None = MISSING,
        parents: List[ArgumentParser] = MISSING,
        formatter_class: Type[HelpFormatter] = MISSING,
        prefix_chars: str = MISSING,
        fromfile_prefix_chars: str | None = MISSING,
        argument_default: Any = MISSING,
        conflict_handler: str = MISSING,
        add_help: bool = MISSING,
        allow_abbrev: bool = MISSING):
    def decorator(func):
        if not hasattr(func, "__subcommand_info__"):
            setattr(func, "__subcommand_info__", _SubCommandInfo())

        subcommand_info: _SubCommandInfo = func.__subcommand_info__
        subcommand_info.func = func
        subcommand_info.save(
            name,
            help=help,
            aliases=aliases,
            prog=prog,
            usage=usage,
            description=description,
            epilog=epilog,
            parents=parents,
            formatter_class=formatter_class,
            prefix_chars=prefix_chars,
            fromfile_prefix_chars=fromfile_prefix_chars,
            argument_default=argument_default,
            conflict_handler=conflict_handler,
            add_help=add_help,
            allow_abbrev=allow_abbrev
        )

        function = inspect.stack()[1].function
        _subcommand_mapping.setdefault(function, set())
        _subcommand_mapping[function].add(func.__name__)

        return func

    return decorator


def subcommand_argument(
        name_or_flag: str,
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
        type: Union[Type[Union[int, float, str]], Callable[[str], T], FileType] = MISSING,
        **kwargs: Any):
    def decorator(func):
        subcommand_argument_info = _SubCommandArgumentInfo()
        subcommand_argument_info.save(
            *[name_or_flag, *name_or_flags],
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
        )

        if not hasattr(func, "__subcommand_info__"):
            setattr(func, "__subcommand_info__", _SubCommandInfo())

        subcommand_info: _SubCommandInfo = func.__subcommand_info__
        subcommand_info.arguments.append(subcommand_argument_info)

        return func

    return decorator


class SubCommandMixin:

    @classmethod
    def _find_command_infos(cls, clazz: Any):
        class_set, class_queue = set(), list()
        class_queue.append(clazz.__class__)
        class_set.add(clazz.__class__)

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

        return sorted(command_infos, key=lambda o: o[0])

    def add_subcommands(self: "BaseCommand", parser: ArgumentParser = None, target: Any = None):

        parser = parser or self._argument_parser
        target = target or self

        subparsers = parser.add_subparsers(help="Commands", required=True)
        for _, command_info in SubCommandMixin._find_command_infos(target):
            command_actions = []
            command_func = getattr(target, command_info.func.__name__)
            command_parser = subparsers.add_parser(command_info.name, **_filter_kwargs(command_info.kwargs))
            command_parser.set_defaults(
                __subcommand_info__=command_info,
                __subcommand_func__=command_func,
                __subcommand_actions__=command_actions,
            )

            for argument in command_info.arguments:
                argument_args = argument.args
                argument_kwargs = dict(argument.kwargs)

                # 解析dest，把注解的参数和方法参数对应上
                dest = argument_kwargs.get("dest", None)
                if not dest:
                    prefix_chars = command_parser.prefix_chars
                    if not argument_args or len(argument_args) == 1 and argument_args[0][0] not in prefix_chars:
                        dest = argument_args[0]
                        argument_kwargs["required"] = MISSING  # 这种方式不能指定required，所以这里设置为MISSING
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

                # 验证一下dest是否在参数列表中，不在就报错
                signature = inspect.signature(command_func)
                if dest not in signature.parameters:
                    raise ValueError(f"Check subcommand argument error, "
                                     f"{command_info} has no `{argument.action.dest}` argument")

                # 根据方法参数的注解，设置一些默认值
                parameter = signature.parameters[dest]
                if "default" not in argument_kwargs:
                    if parameter.default != signature.empty:
                        argument_kwargs.setdefault("default", parameter.default)
                        argument_kwargs.setdefault("required", False)
                    else:
                        argument_kwargs.setdefault("required", True)
                if "action" not in argument_kwargs:
                    if parameter.annotation != signature.empty:
                        if parameter.annotation in (int, float, str):
                            argument_kwargs.setdefault("type", parameter.annotation)
                        elif parameter.annotation == bool:
                            if argument_kwargs.get("default", False):
                                argument_kwargs.setdefault("action", "store_false")
                            else:
                                argument_kwargs.setdefault("action", "store_true")

                command_actions.append(command_parser.add_argument(
                    *argument_args,
                    **_filter_kwargs(argument_kwargs)
                ))

        return subparsers

    def run_subcommand(self: "BaseCommand", args: Namespace) -> Optional[int]:
        if not (hasattr(args, "__subcommand_info__") and
                hasattr(args, "__subcommand_func__") and
                hasattr(args, "__subcommand_actions__")):
            raise CommandError("Not found subcommand")
        command_info = args.__subcommand_info__
        command_func = args.__subcommand_func__
        command_actions = args.__subcommand_actions__
        kwargs = dict()
        for action in command_actions:
            kwargs[action.dest] = getattr(args, action.dest)
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

    def create_argument_parser(
            self,
            *args: Any,
            type: Callable[..., ArgumentParser] = ArgumentParser,
            formatter_class: Type[HelpFormatter] = RawDescriptionHelpFormatter,
            conflict_handler="resolve",
            **kwargs: Any
    ) -> ArgumentParser:
        description = kwargs.pop("description", None)
        if not description:
            description = self.description.strip()
            if description and self.environ.description != NotImplemented:
                description += os.linesep + os.linesep
                description += self.environ.description
        parser = type(
            *args,
            description=description,
            formatter_class=formatter_class,
            conflict_handler=conflict_handler,
            **kwargs
        )
        self.init_base_arguments(parser)
        self.init_arguments(parser)
        return parser

    @cached_property
    def _argument_parser(self) -> ArgumentParser:
        return self.create_argument_parser()

    def init_base_arguments(self, parser: ArgumentParser) -> None:
        pass

    @abc.abstractmethod
    def init_arguments(self, parser: ArgumentParser) -> None:
        pass

    @abc.abstractmethod
    def run(self, args: Namespace) -> Optional[int]:
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

        LogCommandMixin.add_log_options(self)

        if self.environ.version != NotImplemented:
            self._argument_parser.add_argument(
                "--version", action="version", version=self.environ.version
            )

        exit(self(*args, **kwargs))

    def __call__(self, args: Union[List[str], Namespace] = None) -> int:
        try:
            if not isinstance(args, Namespace):
                args = args or sys.argv[1:]
                args = self._argument_parser.parse_args(args, namespace=Namespace())
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

        return exit_code or 0


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
