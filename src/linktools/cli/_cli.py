#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from importlib.util import module_from_spec
from pkgutil import walk_packages

from ._command import Command
from .._environ import logger


def walk_commands(path: str):
    # for entry in sorted(os.scandir(path), key=lambda o: o.name):
    #     entry: os.DirEntry = entry
    #     if entry.is_dir() and not entry.name.startswith("_"):
    #         yield from walk_commands(
    #             os.path.join(path, entry.name),
    #             f"{package}.{entry.name}"
    #         )

    for finder, name, is_pkg in sorted(walk_packages(path=[path]), key=lambda i: i[1]):
        if not is_pkg:
            try:
                spec = finder.find_spec(name)
                module = module_from_spec(spec)
                spec.loader.exec_module(module)
                command = getattr(module, "command", None)
                if command and isinstance(command, Command):
                    yield name, command
            except Exception as e:
                logger.warning(f"Ignore {name}, caused by {e.__class__.__name__}: {e}")
