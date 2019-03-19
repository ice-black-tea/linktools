#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : at_adb.py 
@time    : 2019/03/04
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

from android_tools.adb import Adb, AdbError
from android_tools.argparser import AdbArgumentParser
from android_tools.utils import Utils


def main():
    general_commands = [
        "devices",
        "help",
        "version",
        "connect",
        "disconnect",
        "keygen",
        "wait-for-",
        "start-server",
        "kill-server",
        "reconnect",
    ]

    parser = AdbArgumentParser(description="adb wrapper")
    adb, args = parser.parse_adb_args(sys.argv[1:])

    if not Utils.is_empty(args) and args[0] not in general_commands:
        parser.parse_known_args(args)
        Adb.exec(*["-s", adb.extend(), *args], capture_output=False)
    else:
        Adb.exec(*args, capture_output=False)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
    except AdbError as e:
        print(e)
