#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from importlib.util import module_from_spec
from pkgutil import walk_packages

from ._command import BaseCommand
from .._environ import environ


def walk_commands(path: str):
    for finder, name, is_pkg in sorted(walk_packages(path=[path]), key=lambda i: i[1]):
        if not is_pkg:
            try:
                spec = finder.find_spec(name)
                module = module_from_spec(spec)
                spec.loader.exec_module(module)
                command = getattr(module, "command", None)
                if command and isinstance(command, BaseCommand):
                    yield command
            except Exception as e:
                environ.logger.warning(f"Ignore {name}, caused by {e.__class__.__name__}: {e}")
