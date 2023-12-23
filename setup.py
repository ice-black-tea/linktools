#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : setup.py
@time    : 2018/11/25
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
import json
import os
import pkgutil
from types import ModuleType

from setuptools import setup


class ConsoleScripts(list):

    def append_script(self, script_name, module_name):
        self.append(f"{script_name.replace('_', '-')} = {module_name}:command.main")
        return self

    def append_module(self, path, script_prefix, module_prefix):
        for _, module_name, _ in pkgutil.iter_modules([path]):
            if not module_name.startswith("_"):
                self.append_script(
                    f"{script_prefix}-{module_name.replace('_', '-')}",
                    f"{module_prefix}.{module_name}",
                )
        return self


if __name__ == '__main__':

    def get_path(*paths):
        return os.path.join(
            os.path.abspath(os.path.dirname(__file__)),
            *paths
        )

    version = ModuleType("version")
    with open(get_path("src", "linktools", "version.py"), mode="rb") as fd:
        exec(compile(fd.read(), "version", "exec"), version.__dict__)

    with open(get_path("dependencies.json"), "rt", encoding="utf-8") as fd:
        data = json.load(fd)
        install_requires = data.get("dependencies")
        extras_require = data.get("optional-dependencies")
        all_requires = []
        for requires in extras_require.values():
            all_requires.extend(requires)
        extras_require["all"] = all_requires

    scripts = ConsoleScripts().append_script(
        script_name="lt",
        module_name="linktools.__main__",
    ).append_module(
        get_path("src", "linktools", "cli", "commands", "common"),
        module_prefix="linktools.cli.commands.common",
        script_prefix="ct",
    ).append_module(
        get_path("src", "linktools", "cli", "commands", "android"),
        module_prefix="linktools.cli.commands.android",
        script_prefix="at",
    ).append_module(
        get_path("src", "linktools", "cli", "commands", "ios"),
        module_prefix="linktools.cli.commands.ios",
        script_prefix="it",
    )

    setup(
        version=version.__version__,
        install_requires=install_requires,
        extras_require=extras_require,
        entry_points={"console_scripts": scripts},
    )
