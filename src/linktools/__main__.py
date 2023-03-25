#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : __main__.py 
@time    : 2022/12/13
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
import os
from argparse import ArgumentParser
from typing import Optional

from rich import get_console
from rich.tree import Tree

from . import cli
from ._environ import environ
from .decorator import cached_property
from .version import __description__


class CategoryInfo:

    def __init__(self, name: str, prefix: str, description: str):
        self.name = name
        self.prefix = prefix
        self.description = description

    def __repr__(self):
        return self.name


class CommandInfo:

    def __init__(self, name: str, category: CategoryInfo, command: cli.Command):
        self.name = name
        self.category = category
        self.command = command

    @property
    def description(self):
        return self.command.description

    def __repr__(self):
        return self.name


class Command(cli.Command):

    @cached_property
    def _commands(self):
        commands = {}
        module_path = os.path.join(environ.root_path, "cli", "commands")
        module_categories = (
            CategoryInfo(name="common", prefix="ct-", description=""),
            CategoryInfo(name="android", prefix="at-", description=""),
            CategoryInfo(name="ios", prefix="it-", description=""),
        )

        for category in module_categories:
            commands[category] = []
            path = os.path.join(module_path, category.name)
            for name, command in cli.walk_commands(path):
                commands[category].append(
                    CommandInfo(
                        name=name,
                        category=category,
                        command=command,
                    )
                )
        return commands

    def add_arguments(self, parser: ArgumentParser) -> None:
        sub_parsers = parser.add_subparsers()
        for category, commands in self._commands.items():
            parser = sub_parsers.add_parser(
                category.name,
                description=category.description
            )
            parser.set_defaults(help=parser.print_help)
            catalog_parser = parser.add_subparsers()
            for command in commands:
                parser = catalog_parser.add_parser(
                    command.name,
                    help=command.description,
                    add_help=False,
                    prefix_chars=chr(0)
                )
                parser.add_argument("args", nargs="...")
                parser.set_defaults(func=command.command)

    def run(self, args: [str]) -> Optional[int]:
        args = self.argument_parser.parse_args(args)
        if hasattr(args, "func") and hasattr(args, "args"):
            return args.func(args.args)
        elif hasattr(args, "help"):
            return args.help()

        tree = Tree("📎 All commands")
        for category, commands in self._commands.items():
            node = tree.add(f"📖 {category}")
            for command in commands:
                node.add(f"👉 {command.category.prefix}[bold red]{command.name}[/bold red]: {command.description}")

        console = get_console()
        console.print(__description__, highlight=False)
        console.print(tree, highlight=False)


command = Command()
if __name__ == '__main__':
    command.main()
