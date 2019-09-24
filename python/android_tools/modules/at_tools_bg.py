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
import _thread as thread
import subprocess
import sys
import time

from android_tools.argparser import ArgumentParser
from android_tools.tools import tools


def get_parser():
    parser = ArgumentParser(description='tools wrapper')
    parser.add_argument('tool', choices=sorted([t.name for t in iter(tools)]))
    return parser


if __name__ == "__main__":
    if len(sys.argv) < 2:
        get_parser().print_usage()
        exit(-1)

    opt = sys.argv[1]
    args = sys.argv[2:]

    if tools[opt] is not None:
        thread.start_new_thread(
            lambda: tools[opt].exec(*args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE), ())
        time.sleep(0.5)
    elif opt == "-h" or opt == "--help":
        get_parser().parse_args(["-h"])
    elif opt == "-v" or opt == "--version":
        get_parser().parse_args(["-v"])
    else:
        get_parser().print_usage()
        exit(-1)
