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
import sys

from linktools import ArgumentParser
from linktools import tools


def get_parser():
    parser = ArgumentParser(description='tools wrapper')
    parser.add_argument('tool', choices=sorted([name for name in iter(tools)]))
    return parser


if __name__ == "__main__":
    if len(sys.argv) < 2:
        get_parser().print_usage()
        exit(-1)

    opt = sys.argv[1]
    args = sys.argv[2:]

    if tools[opt] is not None:
        process, _, _ = tools[opt].exec(*args)
        exit(process.returncode)
    elif opt == "-h" or opt == "--help":
        get_parser().parse_args(["-h"])
    elif opt == "-v" or opt == "--version":
        get_parser().parse_args(["-v"])
    else:
        get_parser().print_usage()
        exit(-1)
