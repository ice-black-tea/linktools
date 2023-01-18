#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import importlib
import os
import pkgutil
from typing import Dict, List

from linktools import __name__ as module_name, environ, logger
from ._command import Command


class CatalogInfo:

    def __init__(self, name: str, prefix: str, description: str):
        self.name = name
        self.prefix = prefix
        self.description = description

    def __repr__(self):
        return self.name


class CommandInfo:

    def __init__(self, name: str, module: str, catalog: CatalogInfo, command: Command):
        self.name = name
        self.module = module
        self.catalog = catalog
        self.command = command

    @property
    def description(self):
        return self.command.description

    def __repr__(self):
        return self.name


command_module_path = os.path.join(environ.root_path, "cli", "commands")
command_module_package = f"{module_name}.cli.commands"
command_catalogs = (
    CatalogInfo(name="common", prefix="ct-", description=""),
    CatalogInfo(name="android", prefix="at-", description=""),
    CatalogInfo(name="ios", prefix="it-", description=""),
)

commands = None


def get_commands() -> Dict[CatalogInfo, List[CommandInfo]]:
    global commands
    if commands:
        return commands

    result = {catalog: [] for catalog in command_catalogs}
    for module, command in walk_commands():
        for catalog in command_catalogs:
            prefix = f"{command_module_package}.{catalog.name}."
            if module.startswith(prefix):
                result[catalog].append(CommandInfo(
                    name=module[len(prefix):],
                    module=module,
                    catalog=catalog,
                    command=command,
                ))
                break

    commands = result
    return commands


def walk_commands(path: str = command_module_path, package: str = command_module_package):
    for entry in sorted(os.scandir(path), key=lambda o: o.name):
        entry: os.DirEntry = entry
        if entry.is_dir() and not entry.name.startswith("_"):
            yield from walk_commands(
                os.path.join(path, entry.name),
                f"{package}.{entry.name}"
            )

    for _, name, is_pkg in sorted(pkgutil.walk_packages(path=[path], prefix=f"{package}."), key=lambda i: i[1]):
        if not is_pkg:
            try:
                module = importlib.import_module(name)
                command = getattr(module, "command")
                if command and isinstance(command, Command):
                    yield name, command
            except Exception as e:
                logger.debug(f"import {name} error, skip: {e}")
