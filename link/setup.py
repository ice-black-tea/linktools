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
import functools
import os
import pkgutil
from distutils.core import setup
from types import ModuleType

from setuptools import find_packages

if __name__ == '__main__':
    get_path = functools.partial(
        os.path.join,
        os.path.abspath(os.path.dirname(__file__))
    )

    version = ModuleType("version")
    version_path = get_path("linktools", "version.py")
    with open(version_path, mode="rb") as fd:
        exec(compile(fd.read(), "version", "exec"), version.__dict__)

    description_path = get_path("README.md")
    with open(description_path, "r") as fd:
        description = fd.read()

    def extend_scripts(script_module, script_prefix):
        scripts_path = get_path("linktools", "scripts", script_module)
        for _, module_name, _ in pkgutil.iter_modules([scripts_path]):
            if not module_name.startswith("_"):
                scripts.append("{script_prefix}-{script_name} = {module_prefix}.{module_name}:main".format(
                    script_prefix=script_prefix,
                    script_name=module_name.replace("_", "-"),
                    module_prefix=f"linktools.scripts.{script_module}",
                    module_name=module_name
                ))

    scripts = []
    extend_scripts(script_module="common", script_prefix="ct")
    extend_scripts(script_module="android", script_prefix="at")
    extend_scripts(script_module="ios", script_prefix="it")

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
        packages=find_packages(),
        entry_points={"console_scripts": scripts},
    )
