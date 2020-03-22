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

from linktools import tools
from linktools.android.argparser import ArgumentParser


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
        process = tools[opt].popen(*args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            process.wait(0)
        except subprocess.TimeoutExpired as e:
            pass
    elif opt == "-h" or opt == "--help":
        get_parser().parse_args(["-h"])
    elif opt == "-v" or opt == "--version":
        get_parser().parse_args(["-v"])
    else:
        get_parser().print_usage()
        exit(-1)
