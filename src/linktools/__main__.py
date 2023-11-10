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
from argparse import ArgumentParser, Namespace
from typing import Optional, List, Dict

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
        CategoryInfo(name="common", prefix="ct-", description="e.g. grep, shell, etc."),
        CategoryInfo(name="android", prefix="at-", description="e.g. adb, fastboot, etc."),
        CategoryInfo(name="ios", prefix="it-", description="e.g. sib, ssh, etc."),
    )

    @cached_property
    def command_infos(self) -> Dict[CategoryInfo, List[CommandInfo]]:
        command_infos = {}
        for category_info in self.module_categories:
            command_infos[category_info] = []
            path = os.path.join(self.module_path, category_info.name)
            for command in walk_commands(path):
                command_infos[category_info].append(
                    CommandInfo(
                        category=category_info,
                        command=command,
                    )
                )
        return command_infos

    def init_arguments(self, parser: ArgumentParser) -> None:
        catalog_parsers = parser.add_subparsers(required=True)
        for category_info, command_infos in self.command_infos.items():
            catalog_parser = catalog_parsers.add_parser(
                category_info.name,
                help=category_info.description
            )
            command_parsers = catalog_parser.add_subparsers(required=True)
            for command_info in command_infos:
                command_parser = command_info.command.create_argument_parser(
                    command_info.name,
                    type=command_parsers.add_parser,
                    help=command_info.description,
                )
                command_parser.set_defaults(func=command_info.command)

    def run(self, args: Namespace) -> Optional[int]:
        if hasattr(args, "func") and callable(args.func):
            return args.func(args)

        tree = Tree("📎 All commands")
        for category, commands in self.command_infos.items():
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
