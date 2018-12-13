#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : at_tools.py
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
import argparse
import sys

from android_tools import tools, utils


def get_parser():
    parser = argparse.ArgumentParser(description='tools wrapper')
    parser.add_argument('tool', choices=sorted([key for key in tools.items]))
    return parser


if __name__ == "__main__":

    if len(sys.argv) < 2:
        get_parser().print_usage()
        exit(-1)

    opt = sys.argv[1]
    args = sys.argv[2:]

    tool = utils.item(tools.items, opt)
    if tool is not None:
        process = tool.exec(*args)
        exit(process.returncode)
    elif opt == "-h" or opt == "--help":
        get_parser().print_help()
        exit(0)
    else:
        get_parser().print_usage()
        exit(-1)
