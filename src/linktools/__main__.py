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
from rich.tree import Tree

from . import utils
from ._environ import resource


class Script(utils.ConsoleScript):

    def _get_description(self) -> str:
        return "linktools toolkit"

    def _add_arguments(self, parser: ArgumentParser) -> None:
        pass

    def _run(self, args: [str]) -> Optional[int]:
        self.argument_parser.parse_args(args)

        path = resource.get_script_path()
        prefix = "linktools.scripts"

        tree = Tree(f"📂 scripts")
        for module, script in self._walk_scripts(path, prefix):
            tree.add(f"🐍 [bold red]{module}[/bold red]: {script.description}")

        console = get_console()
        console.print(tree)

        return

    def _walk_scripts(self, path: str, prefix: str):
        for entry in sorted(os.scandir(path), key=lambda o: o.name):
            entry: os.DirEntry = entry
            if entry.is_dir() and not entry.name.startswith("_"):
                yield from self._walk_scripts(
                    os.path.join(path, entry.name),
                    f"{prefix}.{entry.name}"
                )

        for _, name, is_pkg in sorted(pkgutil.walk_packages(path=[path]), key=lambda i: i[1]):
            if not is_pkg:
                try:
                    module = importlib.import_module(f"{prefix}.{name}")
                    script = getattr(module, "script")
                    if script and isinstance(script, utils.ConsoleScript):
                        yield f"{prefix}.{name}", script
                except Exception as e:
                    self.logger.debug(f"import {prefix}.{name} error, skip: {e}")


script = Script()
if __name__ == '__main__':
    script.main()
