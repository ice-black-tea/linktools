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

    scripts = []
    scripts_path = get_path("linktools", "scripts")
    for _, name, _ in pkgutil.iter_modules([scripts_path]):
        scripts.append("{name} = linktools.scripts.{name}:main".format(name=name))

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
