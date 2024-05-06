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
   /  oooooooooooooooo  .o.  oooo /,   `,"-----------
  / ==ooooooooooooooo==.o.  ooo= //   ,``--{)B     ,"
 /_==__==========__==_ooo__ooo=_/'   /___________,"
"""
from argparse import ArgumentParser, Namespace
from typing import Optional

from linktools import utils

from linktools.cli import AndroidCommand


class Command(AndroidCommand):
    """
    Debug android-tools.apk
    """

    def init_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("-p", "--privilege", action="store_true", default=False,
                            help="run with root privilege")
        parser.add_argument("-u", "--user", action="store",
                            help="run with user privilege")
        parser.add_argument("agent_args", nargs="...", help="agent args")

    def run(self, args: Namespace) -> Optional[int]:
        device = args.device_picker.pick()
        process = device.popen(
            *device.make_shell_args(
                *device.make_agent_args(*args.agent_args),
                privilege=args.privilege,
                user=args.user
            )
        )
        return process.call()


command = Command()
if __name__ == "__main__":
    command.main()
