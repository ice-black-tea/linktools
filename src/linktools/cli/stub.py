#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : stub.py
@time    : 2024/8/6 16:34 
@site    : https://github.com/ice-black-tea
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
import sys

from ..types import Error

if __name__ == '__main__':

    index = 1

    if len(sys.argv) <= index:
        raise Error("Invalid arguments: missing type")
    type = sys.argv[index]
    index += 1

    if type == "tool":
        from linktools import environ

        if len(sys.argv) <= index:
            raise Error("Invalid arguments: missing name")
        name = sys.argv[index]
        index += 1

        exit(
            environ.get_tool(name, cmdline=None)
            .popen(*sys.argv[index:])
            .call()
        )

    raise Error(f"Invalid arguments: unknown type `{type}`")
