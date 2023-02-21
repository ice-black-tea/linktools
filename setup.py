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
from distutils.core import setup
from types import ModuleType

from setuptools import find_namespace_packages


def get_path(*paths):
    return os.path.join(
        os.path.abspath(os.path.dirname(__file__)),
        *paths
    )


class ConsoleScripts(list):

    def append_script(self, script_name, module_name):
        self.append("{script_name} = {module_name}:command.main".format(
            script_name=script_name.replace("_", "-"),
            module_name=module_name,
        ))
        return self

    def append_module(self, *path, module_prefix, script_prefix):
        scripts_path = get_path(*path)
        for _, module_name, _ in pkgutil.iter_modules([scripts_path]):
            if not module_name.startswith("_"):
                self.append_script(
                    "{script_prefix}-{script_name}".format(
                        script_prefix=script_prefix,
                        script_name=module_name.replace("_", "-")
                    ),
                    "{module_prefix}.{module_name}".format(
                        module_prefix=module_prefix,
                        module_name=module_name
                    )
                )
        return self


if __name__ == '__main__':
    version = ModuleType("version")
    with open(get_path("src", "linktools", "version.py"), mode="rb") as fd:
        exec(compile(fd.read(), "version", "exec"), version.__dict__)

    with open(get_path("README.md"), "rt", encoding="utf-8") as fd:
        description = fd.read()

    with open(get_path("requirements.json"), "rt", encoding="utf-8") as fd:
        data = json.load(fd)
        install_requires = data.get("install_requires")
        extras_require = data.get("extras_require")
        all_requires = []
        for requires in extras_require.values():
            all_requires.extend(requires)
        extras_require["all"] = all_requires

    scripts = ConsoleScripts().append_script(
        script_name="lt",
        module_name="linktools.__main__",
    ).append_module(
        "src", "linktools", "cli", "commands", "common",
        script_prefix="ct",
        module_prefix=f"linktools.cli.commands.common",
    ).append_module(
        "src", "linktools", "cli", "commands", "android",
        script_prefix="at",
        module_prefix=f"linktools.cli.commands.android",
    ).append_module(
        "src", "linktools", "cli", "commands", "ios",
        script_prefix="it",
        module_prefix=f"linktools.cli.commands.ios",
    )

    setup(
        name=getattr(version, "__name__"),
        author=getattr(version, "__author__"),
        version=getattr(version, "__version__"),
        author_email=getattr(version, "__email__"),
        url=getattr(version, "__url__"),
        license="Apache 2.0",

        description=getattr(version, "__summary__"),
        long_description=description,
        long_description_content_type='text/markdown',

        include_package_data=True,
        packages=find_namespace_packages("src"),
        package_dir={'': 'src'},

        python_requires=">=3.6",
        install_requires=install_requires,
        extras_require=extras_require,
        entry_points={"console_scripts": scripts},
    )
