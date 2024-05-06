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
   /  oooooooooooooooo  .o.  oooo /,   `,"-----------
  / ==ooooooooooooooo==.o.  ooo= //   ,``--{)B     ,"
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
        # "wait-for-",
        "start-server",
        "kill-server",
        "reconnect",
        "attach",
        "detach",
    ]

    def main(self, *args, **kwargs) -> None:
        self.environ.config.set_default("SHOW_LOG_LEVEL", False)
        self.environ.config.set_default("SHOW_LOG_TIME", False)
        return super().main(*args, **kwargs)

    def init_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("adb_args", nargs="...", metavar="args", help="adb args")

    def run(self, args: Namespace) -> Optional[int]:
        adb_args = args.adb_args
        if adb_args and adb_args[0] not in self._GENERAL_COMMANDS and not adb_args[0].startswith("wait-for-"):
            device = args.device_picker.pick()
            process = device.popen(*adb_args, capture_output=False)
            return process.call()

        adb = args.device_picker.bridge
        process = adb.popen(*adb_args, capture_output=False)
        return process.call()


command = Command()
if __name__ == "__main__":
    command.main()
