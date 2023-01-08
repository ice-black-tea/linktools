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
from typing import Optional, Dict, List

from rich import get_console
from rich.tree import Tree

from . import utils
from ._environ import resource
from .decorator import cached_property


class _Catalog:

    def __init__(self, name: str, prefix: str):
        self.name = name
        self.prefix = prefix

    def __repr__(self):
        return self.name


class _Command:

    def __init__(self, name: str, module: str, catalog: _Catalog, script: utils.ConsoleScript):
        self.name = name
        self.module = module
        self.catalog = catalog
        self.script = script

    @property
    def description(self):
        return self.script.description

    def __repr__(self):
        return self.name


class Script(utils.ConsoleScript):
    _SCRIPT_MODULE_PREFIX = "linktools.scripts"
    _SCRIPT_CATALOGS = (
        _Catalog(name="common", prefix="ct-"),
        _Catalog(name="android", prefix="at-"),
        _Catalog(name="ios", prefix="it-"),
    )

    @property
    def _description(self) -> str:
        return "linktools toolkit"

    def _add_arguments(self, parser: ArgumentParser) -> None:
        sub_parsers = parser.add_subparsers()
        for catalog in self._SCRIPT_CATALOGS:
            parser = sub_parsers.add_parser(catalog.name, help=f"{catalog} commands")
            parser.set_defaults(help=parser.print_help)
            catalog_parser = parser.add_subparsers()
            for command in self._commands[catalog]:
                parser = catalog_parser.add_parser(
                    command.name,
                    help=command.description,
                    add_help=False,
                    prefix_chars=chr(0)
                )
                parser.add_argument("args", nargs="...")
                parser.set_defaults(func=command.script)

    def _run(self, args: [str]) -> Optional[int]:
        args = self.argument_parser.parse_args(args)
        if hasattr(args, "func") and hasattr(args, "args"):
            return args.func(args.args)
        elif hasattr(args, "help"):
            return args.help()

        tree = Tree("📎 All commands")
        for catalog in self._SCRIPT_CATALOGS:
            node = tree.add(f"📖 {catalog}")
            for command in self._commands[catalog]:
                node.add(f"👉 {command.catalog.prefix}[bold red]{command.name}[/bold red]: {command.description}")

        console = get_console()
        console.print(tree)

    @cached_property
    def _commands(self) -> Dict[_Catalog, List[_Command]]:
        commands = {}
        for catalog in self._SCRIPT_CATALOGS:
            commands[catalog] = []
        for module, script in self._walk_scripts():
            for catalog in self._SCRIPT_CATALOGS:
                prefix = f"{self._SCRIPT_MODULE_PREFIX}.{catalog.name}."
                if module.startswith(prefix):
                    commands[catalog].append(_Command(
                        name=module[len(prefix):],
                        module=module,
                        catalog=catalog,
                        script=script,
                    ))
                    break
        return commands

    def _walk_scripts(self, path: str = resource.get_script_path(), prefix: str = _SCRIPT_MODULE_PREFIX):
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
