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
import importlib
import os
import pkgutil
from argparse import ArgumentParser
from typing import Optional

from rich import get_console
from rich.console import Group
from rich.panel import Panel
from rich.tree import Tree

from . import utils
from ._environ import environ


class Script(utils.ConsoleScript):

    def _get_description(self) -> str:
        return "linktools toolkit"

    def _add_arguments(self, parser: ArgumentParser) -> None:
        pass

    def _run(self, args: [str]) -> Optional[int]:
        args = self.argument_parser.parse_args(args)

        console = get_console()
        console.print(self._walk_scripts(
            Tree(Panel.fit(f"📂 scripts")),
            environ.resource.get_script_path(),
            "linktools.scripts"
        ))

        return

    def _walk_scripts(self, node: Tree, path: str, prefix: str):
        for dir_entry in sorted(os.scandir(path), key=lambda entry: entry.name):
            dir_entry: os.DirEntry = dir_entry
            if dir_entry.is_dir() and not dir_entry.name.startswith("_"):
                self._walk_scripts(
                    node.add(Panel.fit(f"📂 {dir_entry.name}")),
                    os.path.join(path, dir_entry.name),
                    f"{prefix}.{dir_entry.name}"
                )

        for _, name, is_pkg in sorted(pkgutil.walk_packages(path=[path]), key=lambda i: i[1]):
            module = importlib.import_module(f"{prefix}.{name}")
            script = getattr(module, "script")
            if script and isinstance(script, utils.ConsoleScript):
                node.add(Group(
                    Panel.fit(f"🐍 [bold red]{name}[/bold red]: {script.description}", border_style="red"),
                ))

        return node


script = Script()
if __name__ == '__main__':
    script.main()
