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
from argparse import ArgumentParser, Namespace
from typing import Optional

from linktools.cli import AndroidCommand


class Command(AndroidCommand):
    """
    Adb supports managing multiple android devices
    """

    _GENERAL_COMMANDS = [
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

    def init_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("adb_args", nargs="...", metavar="args", help="adb args")

    def run(self, args: Namespace) -> Optional[int]:
        if args.adb_args and args.adb_args[0] not in self._GENERAL_COMMANDS:
            device = args.parse_device()
            process = device.popen(*args.adb_args, capture_output=False)
            return process.call()

        adb = args.parse_device.bridge
        process = adb.popen(*args.adb_args, capture_output=False)
        return process.call()


command = Command()
if __name__ == "__main__":
    command.main()
