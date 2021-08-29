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
from distutils.core import setup
from types import ModuleType

from setuptools import find_packages

if __name__ == '__main__':
    root_path = os.path.abspath(os.path.dirname(__file__))

    requires_path = os.path.join(root_path, "requirements.txt")
    with open(requires_path, "r") as fd:
        install_requires = fd.readlines()

    version = ModuleType("version")
    version_path = os.path.join(root_path, "linktools", "version.py")
    with open(version_path, mode="rb") as fd:
        exec(compile(fd.read(), "version", "exec"), version.__dict__)

    setup(
        name=getattr(version, "__name__"),
        author=getattr(version, "__author__"),
        version=getattr(version, "__version__"),
        author_email=getattr(version, "__email__"),
        url=getattr(version, "__url__"),
        include_package_data=True,
        install_requires=install_requires,
        packages=find_packages(),
    )
