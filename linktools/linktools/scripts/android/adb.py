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

from linktools.android import Adb, AdbError
from linktools.argparser.android import AndroidArgumentParser
from linktools.decorator import entry_point


@entry_point(known_errors=(AdbError,))
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

    parser = AndroidArgumentParser(description="adb wrapper")
    parser.add_argument('adb_args', nargs='...', help="adb args")
    args, extra = parser.parse_known_args()

    adb_args = [*extra, *args.adb_args]
    if not extra:
        if args.adb_args and args.adb_args[0] not in general_commands:
            device = args.parse_device()
            process = device.popen(*adb_args, capture_output=False)
            return process.call()

    process = Adb.popen(*adb_args, capture_output=False)
    return process.call()


if __name__ == '__main__':
    main()
