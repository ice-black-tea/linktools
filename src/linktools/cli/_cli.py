#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import importlib
import os
import pkgutil
from typing import Dict, List

from linktools import __name__ as module_name, environ, logger
from ._command import Command


class CategoryInfo:

    def __init__(self, name: str, prefix: str, description: str):
        self.name = name
        self.prefix = prefix
        self.description = description

    def __repr__(self):
        return self.name


class CommandInfo:

    def __init__(self, name: str, module: str, category: CategoryInfo, command: Command):
        self.name = name
        self.module = module
        self.category = category
        self.command = command

    @property
    def description(self):
        return self.command.description

    def __repr__(self):
        return self.name


commands = None
command_module_path = os.path.join(environ.root_path, "cli", "commands")
command_module_package = f"{module_name}.cli.commands"
command_categories = (
    CategoryInfo(name="common", prefix="ct-", description=""),
    CategoryInfo(name="android", prefix="at-", description=""),
    CategoryInfo(name="ios", prefix="it-", description=""),
)


def get_commands() -> Dict[CategoryInfo, List[CommandInfo]]:
    global commands
    if commands:
        return commands

    result = {}
    for category in command_categories:
        result[category] = []
        path = os.path.join(command_module_path, category.name)
        prefix = f"{command_module_package}.{category.name}."
        for module, command in walk_commands(path, prefix):
            result[category].append(
                CommandInfo(
                    name=module[len(prefix):],
                    module=module,
                    category=category,
                    command=command,
                )
            )

    commands = result
    return commands


def walk_commands(path, prefix):
    # for entry in sorted(os.scandir(path), key=lambda o: o.name):
    #     entry: os.DirEntry = entry
    #     if entry.is_dir() and not entry.name.startswith("_"):
    #         yield from walk_commands(
    #             os.path.join(path, entry.name),
    #             f"{package}.{entry.name}"
    #         )

    for _, name, is_pkg in sorted(pkgutil.walk_packages(path=[path], prefix=prefix), key=lambda i: i[1]):
        if not is_pkg:
            try:
                module = importlib.import_module(name)
                command = getattr(module, "command")
                if command and isinstance(command, Command):
                    yield name, command
            except Exception as e:
                logger.warning(f"Ignore {name}, caused by {e.__class__.__name__}: {e}")
