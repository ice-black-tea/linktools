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
   /  oooooooooooooooo  .o.  oooo /,   `,"-----------
  / ==ooooooooooooooo==.o.  ooo= //   ,``--{)B     ,"
 /_==__==========__==_ooo__ooo=_/'   /___________,"
"""
import json
import os
import pkgutil

import yaml
from jinja2 import Template
from setuptools import setup


def get_path(*paths):
    return os.path.join(
        os.path.abspath(os.path.dirname(__file__)),
        *paths
    )


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

    release = os.environ.get("RELEASE", "false").lower() == "true"
    version = os.environ.get("VERSION", "0.0.1.dev0")
    if version.startswith("v"):
        version = version[len("v"):]

    with open(get_path("src", "linktools", "template", "tools.yml"), "rb") as fd_in, \
            open(get_path("src", "linktools", "assets", "tools.json"), "wt") as fd_out:
        json.dump(
            {
                key: value
                for key, value in yaml.safe_load(fd_in).items()
                if key[0].isupper()
            },
            fd_out
        )

    with open(get_path("src", "linktools", "template", "metadata"), "rt", encoding="utf-8") as fd_in, \
            open(get_path("src", "linktools", "metadata.py"), "wt", encoding="utf-8") as fd_out:
        template = Template(fd_in.read())
        fd_out.write(
            template.render(
                release="True" if release else "False",
                version=version,
            )
        )

    with open(get_path("requirements.yml"), "rt", encoding="utf-8") as fd:
        data = yaml.safe_load(fd)
        # install_requires = dependencies + dev-dependencies
        install_requires = data.get("dependencies")
        if not release:
            install_requires.extend(data.get("dev-dependencies"))
        # extras_require = optional-dependencies
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
        version=version,
        install_requires=install_requires,
        extras_require=extras_require,
        entry_points={"console_scripts": scripts},
    )
