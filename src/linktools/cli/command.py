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
import textwrap
import traceback
from argparse import ArgumentParser, Action, Namespace
from argparse import RawDescriptionHelpFormatter, SUPPRESS, FileType, HelpFormatter
from importlib.util import module_from_spec
from pkgutil import walk_packages
from types import ModuleType, GeneratorType
from typing import Optional, Callable, List, Type, Tuple, Generator, Any, Iterable, Union, Set, Dict, TypeVar

from rich import get_console
from rich.tree import Tree

from .argparse import BooleanOptionalAction
from .._environ import BaseEnviron, environ
from .._rich import LogHandler, is_terminal
from ..decorator import cached_property
from ..metadata import __missing__

T = TypeVar("T")


class CommandError(Exception):
    pass


class SubCommandError(CommandError):
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


def _filter_kwargs(kwargs):
    return {k: v for k, v in kwargs.items() if v is not __missing__}


_subcommand_index: int = 0
_subcommand_map: Dict[str, Set[str]] = {}


class _SubCommandMethodInfo:

    def __init__(self):
        global _subcommand_index
        _subcommand_index += 1
        self.name = None
        self.pass_args = False
        self.index = _subcommand_index
        self.kwargs: Optional[Dict[str, Any]] = None
        self.func: Optional[Callable[..., Optional[int]]] = None
        self.arguments: List[_SubCommandMethodArgumentInfo] = []

    def set_args(self, name: str, **kwargs: Any):
        self.name = name
        self.kwargs = _filter_kwargs(kwargs)
        return self

    def __repr__(self):
        return f"<SubCommandMethod func={self.func.__qualname__}>"


class _SubCommandMethodArgumentInfo:

    def __init__(self):
        self.args: Optional[Tuple[str]] = None
        self.kwargs: Optional[Dict[str, Any]] = None
        self.action: Optional[Union[str, Type[Action]]] = None

    def set_args(self, *args: str, **kwargs: Any):
        self.args = args
        self.kwargs = _filter_kwargs(kwargs)
        return self


def subcommand(
        name: str,
        *,
        help: str = __missing__,
        aliases: List[str] = __missing__,
        prog: str = __missing__,
        usage: str = __missing__,
        description: str = __missing__,
        epilog: str = __missing__,
        parents: List[ArgumentParser] = __missing__,
        formatter_class: Type[HelpFormatter] = __missing__,
        prefix_chars: str = __missing__,
        fromfile_prefix_chars: str = __missing__,
        argument_default: Any = __missing__,
        conflict_handler: str = __missing__,
        add_help: bool = __missing__,
        allow_abbrev: bool = __missing__,
        pass_args: bool = False):
    def decorator(func):
        if not hasattr(func, "__subcommand_info__"):
            setattr(func, "__subcommand_info__", _SubCommandMethodInfo())

        subcommand_info = func.__subcommand_info__
        subcommand_info.func = func
        subcommand_info.pass_args = pass_args
        subcommand_info.set_args(
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

        index = func.__qualname__.rfind(".")
        if index < 0:
            raise SubCommandError(
                f"subcommand decorator must be used in class method, "
                f"but {func.__qualname__} is not")

        class_name = f"{func.__module__}.{func.__qualname__[:index]}"
        func_name = func.__qualname__[index + 1:]

        _subcommand_map.setdefault(class_name, set())
        if func_name in _subcommand_map[class_name]:
            raise SubCommandError(
                f"Redeclared subcommand method '{func.__qualname__}' defined")
        _subcommand_map[class_name].add(func_name)

        return func

    return decorator


def subcommand_argument(
        name_or_flag: str,
        *name_or_flags: str,
        action: Union[str, Type[Action]] = __missing__,
        choices: Iterable[T] = __missing__,
        const: Any = __missing__,
        default: Any = __missing__,
        dest: str = __missing__,
        help: str = __missing__,
        metavar: Union[str, Tuple[str, ...]] = __missing__,
        nargs: Union[int, str] = __missing__,
        required: bool = __missing__,
        type: Union[Type[Union[int, float, str]], Callable[[str], T], FileType] = __missing__,
        **kwargs: Any):
    def decorator(func):
        subcommand_argument_info = _SubCommandMethodArgumentInfo()
        subcommand_argument_info.set_args(
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
            setattr(func, "__subcommand_info__", _SubCommandMethodInfo())

        subcommand_info = func.__subcommand_info__
        subcommand_info.arguments.append(subcommand_argument_info)

        return func

    return decorator


class SubCommand(metaclass=abc.ABCMeta):
    ROOT_ID = ""

    def __init__(self, name: str, description: str, id: str = None, parent_id: str = None):
        self.id = id or name
        self.parent_id = parent_id or self.ROOT_ID
        self.name = name
        self.description = description

    @property
    def has_parent(self):
        return self.parent_id != self.ROOT_ID

    @property
    def is_group(self):
        return isinstance(self, SubCommandGroup)

    def create_parser(self, type: Callable[..., ArgumentParser]) -> ArgumentParser:
        return type(self.name, help=self.description)

    @abc.abstractmethod
    def run(self, args: Namespace):
        pass

    def __repr__(self):
        return f"<SubCommand id={self.id}>"


class SubCommandGroup(SubCommand):

    def create_parser(self, type: Callable[..., ArgumentParser]) -> ArgumentParser:
        parser = type(self.name, help=self.description)
        parser.set_defaults(**{f"__subcommand_help_{id(self):x}__": parser.print_help})
        return parser

    def run(self, args: Namespace):
        attr_name = f"__subcommand_help_{id(self):x}__"
        assert hasattr(args, attr_name)
        func = getattr(args, attr_name)
        return func()


class _SubCommandMethod(SubCommand):

    def __init__(self, info: _SubCommandMethodInfo, target: Any, id: str = None, parent_id: str = None):
        super().__init__(
            id=id,
            parent_id=parent_id,
            name=info.name,
            description=info.kwargs.get("description", None) or info.kwargs.get("help", None) or ""
        )
        self.info = info
        self.target = target

    def create_parser(self, type: Callable[..., ArgumentParser]) -> ArgumentParser:

        actions = []
        method = getattr(self.target, self.info.func.__name__)
        parser = type(self.name, **self.info.kwargs)
        parser.set_defaults(**{f"__subcommand_actions_{id(self):x}__": actions})

        for argument in self.info.arguments:
            argument_args = argument.args
            argument_kwargs = dict(argument.kwargs)

            # 解析dest，把注解的参数和方法参数对应上
            dest = argument_kwargs.get("dest", None)
            if not dest:
                prefix_chars = parser.prefix_chars
                if not argument_args or len(argument_args) == 1 and argument_args[0][0] not in prefix_chars:
                    dest = argument_args[0]
                    argument_kwargs["required"] = __missing__  # 这种方式不能指定required，所以这里设置为MISSING
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
                        raise SubCommandError(
                            f"Parse subcommand argument dest error, "
                            f"{self.info} argument `{', '.join(argument_args)}` require dest=...")
                    dest = dest.replace('-', '_')
                    argument_kwargs["dest"] = dest

            # 验证一下dest是否在参数列表中，不在就报错
            signature = inspect.signature(method)
            if dest not in signature.parameters:
                raise SubCommandError(
                    f"Check subcommand argument error, "
                    f"{self.info} has no `{argument.action.dest}` argument")

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

            actions.append(parser.add_argument(
                *argument_args,
                **_filter_kwargs(argument_kwargs)
            ))

        return parser

    def run(self, args: Namespace):
        method = getattr(self.target, self.info.func.__name__)

        attr_name = f"__subcommand_actions_{id(self):x}__"
        assert hasattr(args, attr_name)
        actions = getattr(args, attr_name)

        method_args = []
        if self.info.pass_args:
            method_args.append(args)

        method_kwargs = dict()
        for action in actions:
            method_kwargs[action.dest] = getattr(args, action.dest)

        return method(*method_args, **method_kwargs)


class SubCommandWrapper(SubCommand):

    def __init__(self, command: "BaseCommand",
                 id: str = None, parent_id: str = None,
                 name: str = None, description: str = None):
        super().__init__(
            id=id,
            parent_id=parent_id,
            name=name or command.name,
            description=description or command.description
        )
        self.command = command

    def create_parser(self, type: Callable[..., ArgumentParser]) -> ArgumentParser:
        return self.command.create_parser(self.name, help=self.description, type=type)

    def run(self, args: Namespace):
        return self.command(args)


class SubCommandMixin:

    def walk_subcommands(self: "BaseCommand", target: Any) -> Generator[SubCommand, None, None]:

        if isinstance(target, SubCommand):
            yield target

        elif isinstance(target, (list, tuple, set, GeneratorType)):
            for item in target:
                yield from self.walk_subcommands(item)

        elif isinstance(target, ModuleType):
            prefix = target.__name__ + "."  # prefix: aaa.
            for finder, name, is_package in walk_packages(path=target.__path__, prefix=prefix):  # name: aaa.bbb.ccc
                module_name = name[len(prefix):]  # bbb.ccc
                parent_module_name = name[len(prefix):name.rfind(".")]  # bbb

                try:
                    spec = finder.find_spec(name)
                    module = module_from_spec(spec)
                    spec.loader.exec_module(module)
                except Exception as e:
                    self.logger.warning(
                        f"Ignore {module_name}, caused by {e.__class__.__name__}: {e}",
                        exc_info=e if environ.debug else None
                    )
                    continue

                if is_package:
                    _name = getattr(module, "__command__", None) or name[name.rfind(".") + 1:]  # ccc
                    _description = getattr(module, "__description__", None) or ""
                    yield SubCommandGroup(_name, _description, id=module_name, parent_id=parent_module_name)
                elif hasattr(module, "command") and isinstance(module.command, BaseCommand):
                    yield SubCommandWrapper(module.command, id=module_name, parent_id=parent_module_name)

        else:
            subcommand_map: Dict[str, List[_SubCommandMethod]] = {}
            for clazz in target.__class__.mro():
                class_name = f"{clazz.__module__}.{clazz.__qualname__}"
                if class_name not in _subcommand_map:
                    continue
                for func_name in _subcommand_map[class_name]:
                    if not hasattr(clazz, func_name):
                        continue
                    func = getattr(clazz, func_name)
                    if not hasattr(func, "__subcommand_info__"):
                        continue
                    info: _SubCommandMethodInfo = func.__subcommand_info__
                    subcommand = _SubCommandMethod(info, target)
                    subcommand_map.setdefault(subcommand.name, list())
                    subcommand_map[info.name].append(subcommand)

            command_infos: List[Tuple[int, _SubCommandMethod]] = []
            for name, subcommands in subcommand_map.items():
                command_infos.append((min([c.info.index for c in subcommands]), subcommands[0]))
            for _, subcommand in sorted(command_infos, key=lambda o: o[0]):
                yield subcommand

    def add_subcommands(
            self: "BaseCommand",
            parser: ArgumentParser = None,
            target: Any = None,
            required: bool = False) -> List[SubCommand]:

        subcommands = []

        target = target or self
        parser = parser or self._argument_parser
        parser.set_defaults(**{f"__subcommands_{id(self):x}__": subcommands})

        subparsers_map = {}
        subparsers = parser.add_subparsers(metavar="COMMAND", help="Command Help")
        subparsers.required = required

        for subcommand in self.walk_subcommands(target):
            subcommands.append(subcommand)

            parent_subparsers = subparsers
            if subcommand.has_parent:
                parent_subparsers = subparsers_map.get(subcommand.parent_id, None)
                if not parent_subparsers:
                    raise SubCommandError(f"Subcommand {subcommand} has no parent subparser")

            parser = subcommand.create_parser(type=parent_subparsers.add_parser)
            parser.set_defaults(**{f"__subcommand_{id(self):x}__": subcommand})

            if subcommand.is_group:
                _subparsers = parser.add_subparsers(metavar="COMMAND", help="Command Help")
                _subparsers.required = False
                subparsers_map[subcommand.id] = _subparsers

        return subcommands

    def run_subcommand(self: "BaseCommand", args: Namespace) -> Optional[int]:

        name = f"__subcommand_{id(self):x}__"
        if hasattr(args, name):
            subcommand = getattr(args, name)
            if isinstance(subcommand, SubCommand):
                return subcommand.run(args)

        raise SubCommandError("Not found subcommand")

    def print_subcommands(self: "BaseCommand", args: Namespace):

        name = f"__subcommands_{id(self):x}__"
        if not hasattr(args, name):
            raise SubCommandError("No subcommand has been added yet")

        tree = Tree("📎 All commands")
        nodes: Dict[str, Tree] = {}
        for subcommand in getattr(args, name):
            node = nodes.get(subcommand.parent_id) if subcommand.has_parent else tree
            if subcommand.is_group:
                text = f"📖 [underline red]{subcommand.name}[/underline red]"
                if subcommand.description:
                    text = f"{text}: {subcommand.description}"
                nodes[subcommand.id] = node.add(text)
            else:
                text = f"👉 [bold red]{subcommand.name}[/bold red]"
                if subcommand.description:
                    text = f"{text}: {subcommand.description}"
                nodes[subcommand.id] = node.add(text)

        console = get_console()
        if self.environ.description != NotImplemented:
            console.print(self.environ.description, highlight=False)
        console.print(tree, highlight=False)


class BaseCommand(LogCommandMixin, SubCommandMixin, metaclass=abc.ABCMeta):

    @property
    def name(self):
        name = self.__module__
        index = name.rfind(".")
        if index >= 0:
            name = name[index + 1:]
        return name

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

    def create_parser(
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
        return self.create_parser()

    def init_base_arguments(self, parser: ArgumentParser) -> None:
        pass

    @abc.abstractmethod
    def init_arguments(self, parser: ArgumentParser) -> None:
        pass

    @abc.abstractmethod
    def run(self, args: Namespace) -> Optional[int]:
        pass

    def main(self, *args, **kwargs) -> None:
        if is_terminal():
            logging.basicConfig(
                level=logging.INFO,
                format="%(message)s",
                datefmt="[%X]",
                handlers=[LogHandler(self.environ)]
            )
        else:
            logging.basicConfig(
                level=logging.INFO,
                format="[%(asctime)s] %(levelname)s %(module)s %(funcName)s %(message)s",
                datefmt="%H:%M:%S"
            )

        self.add_log_options()

        if self.environ.version != NotImplemented:
            self._argument_parser.add_argument(
                "--version", action="version", version=self.environ.version
            )

        exit(self(*args, **kwargs))

    def __call__(self, args: Union[List[str], Namespace] = None) -> int:
        try:
            if not isinstance(args, Namespace):
                parser = self._argument_parser
                try:
                    import argcomplete
                    argcomplete.autocomplete(parser)
                except ModuleNotFoundError:
                    pass
                args = parser.parse_args(args)

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
