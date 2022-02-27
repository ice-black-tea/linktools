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

from linktools.android import Adb, AdbError, AndroidArgumentParser
from linktools.decorator import entry_point


@entry_point(known_errors=[AdbError])
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
    if len(adb_args) == 0:
        process = Adb.popen(capture_output=False)
        process.communicate()
        return process.returncode

    # 如果第一个不是"-"开头的参数，并且参数需要添加设备，就额外添加"-s serial"参数
    if not adb_args[0].startswith("-"):
        if adb_args[0] not in general_commands:
            device = args.parse_device()
            device.exec(*adb_args, capture_output=False)
            return

    Adb.exec(*adb_args, capture_output=False)


if __name__ == '__main__':
    main()
