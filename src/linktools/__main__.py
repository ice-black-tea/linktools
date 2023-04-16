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

from ._environ import environ
from .cli import BaseCommand, walk_commands
from .decorator import cached_property


class CategoryInfo:

    def __init__(self, name: str, prefix: str, description: str):
        self.name = name
        self.prefix = prefix
        self.description = description

    def __repr__(self):
        return self.name


class CommandInfo:

    def __init__(self, category: CategoryInfo, command: BaseCommand):
        self.category = category
        self.command = command

    @property
    def name(self):
        return self.command.name

    @property
    def description(self):
        return self.command.description

    def __repr__(self):
        return self.name


class Command(BaseCommand):
    module_path = environ.get_cli_path("commands")
    module_categories = (
        CategoryInfo(name="common", prefix="ct-", description=""),
        CategoryInfo(name="android", prefix="at-", description=""),
        CategoryInfo(name="ios", prefix="it-", description=""),
    )

    @cached_property
    def commands(self):
        commands = {}
        for category in self.module_categories:
            commands[category] = []
            path = os.path.join(self.module_path, category.name)
            for command in walk_commands(path):
                commands[category].append(
                    CommandInfo(
                        category=category,
                        command=command,
                    )
                )
        return commands

    def init_arguments(self, parser: ArgumentParser) -> None:
        sub_parsers = parser.add_subparsers()
        for category, commands in self.commands.items():
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
        args = self.parse_args(args)
        if hasattr(args, "func") and hasattr(args, "args"):
            return args.func(args.args)
        elif hasattr(args, "help"):
            return args.help()

        tree = Tree("📎 All commands")
        for category, commands in self.commands.items():
            node = tree.add(f"📖 {category}")
            for command in commands:
                node.add(f"👉 {command.category.prefix}[bold red]{command.name}[/bold red]: {command.description}")

        console = get_console()
        if environ.description != NotImplemented:
            console.print(environ.description, highlight=False)
        console.print(tree, highlight=False)


command = Command()
if __name__ == '__main__':
    command.main()
