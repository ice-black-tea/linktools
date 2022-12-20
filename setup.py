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
        self.append("{script_name} = {module_name}:script.main".format(
            script_name=script_name.replace("_", "-"),
            module_name=module_name,
        ))

    def extend_modules(self, *path, module_prefix, script_prefix):
        scripts_path = get_path(*path)
        for _, module_name, _ in pkgutil.iter_modules([scripts_path]):
            if not module_name.startswith("_"):
                self.append("{script_prefix}-{script_name} = {module_prefix}.{module_name}:script.main".format(
                    script_prefix=script_prefix,
                    script_name=module_name.replace("_", "-"),
                    module_prefix=module_prefix,
                    module_name=module_name
                ))


if __name__ == '__main__':

    version = ModuleType("version")
    version_path = get_path("src", "linktools", "version.py")
    with open(version_path, mode="rb") as fd:
        exec(compile(fd.read(), "version", "exec"), version.__dict__)

    description_path = get_path("README.md")
    with open(description_path, "r") as fd:
        description = fd.read()

    scripts = ConsoleScripts()
    scripts.append_script("lt", "linktools.__main__")
    scripts.extend_modules(
        "src", "linktools", "scripts", "common",
        script_prefix="ct",
        module_prefix=f"linktools.scripts.common"
    )
    scripts.extend_modules(
        "src", "linktools", "scripts", "android",
        script_prefix="at",
        module_prefix=f"linktools.scripts.android")
    scripts.extend_modules(
        "src", "linktools", "scripts", "ios",
        script_prefix="it",
        module_prefix=f"linktools.scripts.ios"
    )

    setup(
        name=getattr(version, "__name__"),
        author=getattr(version, "__author__"),
        version=getattr(version, "__version__"),
        author_email=getattr(version, "__email__"),
        url=getattr(version, "__url__"),

        description=getattr(version, "__name__"),
        long_description=description,
        long_description_content_type='text/markdown',

        include_package_data=True,
        packages=find_namespace_packages("src"),
        package_dir={'': 'src'},

        entry_points={"console_scripts": scripts},
    )
