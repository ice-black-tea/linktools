#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : ATAdb.py
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

from linktools import utils, logger
from linktools.android import Adb, AdbError, AdbArgumentParser


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
    args, extras = parser.parse_known_args()

    if not utils.is_empty(extras) and extras[0] not in general_commands:
        Adb.exec("-s", args.parse_adb_serial(), *extras, capture_output=False)
    else:
        Adb.exec(*extras, capture_output=False)


if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt, EOFError, AdbError) as e:
        logger.error(e)
    except Exception as e:
        logger.error(traceback_error=True)
