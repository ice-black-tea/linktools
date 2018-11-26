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

import ast
import sys
from setuptools import setup


def get_version(path, key="__version__"):
    with open(path) as f:
        source = f.read()
    module = ast.parse(source)
    for e in module.body:
        if isinstance(e, ast.Assign) and \
                len(e.targets) == 1 and \
                e.targets[0].id == key and \
                isinstance(e.value, ast.Str):
            return e.value.s
    raise RuntimeError('%s not found' % key)


if __name__ == '__main__':

    setup(
        name="android-tools",
        author="Hu Ji",
        version=get_version("android_tools/commons/version.py"),
        author_email="669898595@qq.com",
        packages=["android_tools", "android_tools/commons"],
        url="https://github.com/ice-black-tea/android-library",
    )
