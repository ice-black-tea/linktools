#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : at_call_agent.py
@time    : 2018/12/02
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
from argparse import ArgumentParser
from typing import Optional

from linktools import cli


class Command(cli.AndroidCommand):
    """
    Debug android-tools.apk
    """

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("-p", "--privilege", action="store_true", default=False,
                            help="run with root privilege")
        parser.add_argument("agent_args", nargs="...", help="agent args")

    def run(self, args: [str]) -> Optional[int]:
        args = self.argument_parser.parse_args(args)
        device = args.parse_device()
        adb_args = [
            "CLASSPATH=%s" % device.init_agent(),
            "app_process", "/", device.agent_info["main"],
            *args.agent_args
        ]
        adb_args = ["shell", *adb_args] \
            if not args.privilege or device.uid == 0 \
            else ["shell", "su", "-c", *adb_args]
        process = device.popen(*adb_args)
        return process.call()


command = Command()
if __name__ == "__main__":
    command.main()
