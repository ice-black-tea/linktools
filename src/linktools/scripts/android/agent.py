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

from linktools import utils


class Script(utils.AndroidScript):

    def _get_description(self) -> str:
        return "used for debugging android-tools.apk"

    def _add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument('-p', '--privilege', action='store_true', default=False,
                            help='run with root privilege')
        parser.add_argument('agent_args', nargs='...', help="agent args")

    def _run(self, args: [str]) -> Optional[int]:
        args = self.argument_parser.parse_args(args)
        device = args.parse_device()
        device.call_agent(*args.agent_args, privilege=args.privilege, capture_output=False)
        return


script = Script()
if __name__ == '__main__':
    script.main()
