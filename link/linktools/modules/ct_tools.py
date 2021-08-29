#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : TTools.py
@time    : 2018/12/11
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
import subprocess
import sys

from linktools import ArgumentParser
from linktools import tools

if __name__ == "__main__":
    tool_names = sorted([tool.name for tool in iter(tools)])

    parser = ArgumentParser(description='tools wrapper')
    parser.add_argument('-d', '--daemon', action='store_true', default=False,
                        help='run tools as a daemon')
    parser.add_argument('tool', nargs='...', choices=tool_names)

    args = parser.parse_args()
    if len(args.tool) == 0 or args.tool[0] not in tool_names:
        parser.print_help()
        exit(-1)

    tool_name = args.tool[0]
    tool_args = args.tool[1:]

    if args.daemon:
        process = tools[tool_name].popen(
            *tool_args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        try:
            process.wait(0)
        except subprocess.TimeoutExpired as e:
            pass
    else:
        process, _, _ = tools[tool_name].exec(*tool_args)
        exit(process.returncode)
