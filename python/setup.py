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

from distutils.core import setup


def get_module_value(source, key):
    module = ast.parse(source)
    for e in module.body:
        if isinstance(e, ast.Assign) and \
                len(e.targets) == 1 and \
                e.targets[0].id == key and \
                isinstance(e.value, ast.Str):
            return e.value.s
    raise RuntimeError('%s not found' % key)


if __name__ == '__main__':

    with open("android_tools/commons/version.py", "rt") as f:
        source = f.read()

    setup(
        name=get_module_value(source, "__module__"),
        author=get_module_value(source, "__author__"),
        version=get_module_value(source, "__version__"),
        author_email=get_module_value(source, "__email__"),
        packages=["android_tools", "android_tools/commons"],
        url=get_module_value(source, "__url__"),
    )
