#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : argparse.py 
@time    : 2023/8/25
@site    : https://github.com/ice-black-tea
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
import abc
import argparse
import sys
import typing

from .. import utils

if sys.version_info < (3, 10):

    _orig_get_action_name = getattr(argparse, "_get_action_name", None)
    if _orig_get_action_name is not None and callable(_orig_get_action_name):
        def _get_action_name(argument):
            result = _orig_get_action_name(argument)
            if result is None:
                if argument.choices:
                    return '{' + ','.join(argument.choices) + '}'
            return result

        setattr(argparse, "_get_action_name", _get_action_name)


##############################
# argparse types
##############################

def range_type(min: int, max: int):
    def wrapper(o):
        value = utils.int(o)
        if min <= value <= max:
            return value
        raise ValueError("value not in range %s-%s" % (min, max))

    return wrapper


##############################
# argparse actions
##############################

if not hasattr(argparse, "BooleanOptionalAction"):
    class BooleanOptionalAction(argparse.Action):
        def __init__(self,
                     option_strings,
                     dest,
                     default=None,
                     type=None,
                     choices=None,
                     required=False,
                     help=None,
                     metavar=None):

            _option_strings = []
            for option_string in option_strings:
                _option_strings.append(option_string)

                if option_string.startswith('--'):
                    option_string = '--no-' + option_string[2:]
                    _option_strings.append(option_string)

            super().__init__(
                option_strings=_option_strings,
                dest=dest,
                nargs=0,
                default=default,
                type=type,
                choices=choices,
                required=required,
                help=help,
                metavar=metavar)

        def __call__(self, parser, namespace, values, option_string=None):
            if option_string in self.option_strings:
                setattr(namespace, self.dest, not option_string.startswith('--no-'))

        def format_usage(self):
            return ' | '.join(self.option_strings)

else:
    BooleanOptionalAction = argparse.BooleanOptionalAction


class KeyValueAction(argparse.Action):

    def __init__(self,
                 option_strings,
                 dest,
                 nargs=None,
                 default=None,
                 required=False,
                 help=None,
                 metavar="KEY=VALUE"):

        super().__init__(
            option_strings=option_strings,
            dest=dest,
            nargs=nargs,
            default=default,
            # type=dict,
            required=required,
            help=help,
            metavar=metavar)

    def __call__(self, parser, namespace, value, option_string=None):
        dest = getattr(namespace, self.dest) or {}

        if value:
            if isinstance(value, str):
                value = [value]
            for item in value:
                kv = item.split("=", 1)
                k = kv[0]
                v = kv[1] if len(kv) >= 2 else ""
                if not isinstance(dest, dict):
                    try:
                        setattr(dest, k, v)
                    except Exception as e:
                        raise argparse.ArgumentError(self, str(e))
                else:
                    dest[k] = v

        setattr(namespace, self.dest, dest)


##############################
# auto complete
##############################

if typing.TYPE_CHECKING:
    import argcomplete

auto_complete: "typing.Optional[argcomplete]" = None
try:
    import argcomplete

    auto_complete = argcomplete
except ModuleNotFoundError:
    pass

if auto_complete:

    class ParserCompleter(abc.ABC):

        @abc.abstractmethod
        def get_parser(self) -> argparse.ArgumentParser:
            pass

        @abc.abstractmethod
        def get_args(self, parsed_args: argparse.Namespace, **kwargs) -> typing.Optional[typing.List[str]]:
            pass

        def __call__(self, *, parsed_args, **kwargs):
            completions = {}

            args = self.get_args(parsed_args, **kwargs)
            if args is None:
                return completions

            finder = auto_complete.CompletionFinder(self.get_parser())
            cmdline = f"{utils.list2cmdline(args)} "

            state = 0
            while True:
                item = finder.rl_complete(cmdline, state)
                if item is None:
                    break
                key = item[len(cmdline):]
                completions[key] = finder.get_display_completions().get(key, "")
                state += 1

            return completions

else:
    ParserCompleter = None
