#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : TTools.py
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
import json
import subprocess
from argparse import ArgumentParser
from typing import Optional

from linktools import tools, logger, cli


class Command(cli.Command):
    """
    Tools downloaded from the web
    """

    _TOOL_NAMES = sorted([tool.name for tool in iter(tools)])

    def _add_arguments(self, parser: ArgumentParser) -> None:
        group = parser.add_mutually_exclusive_group()
        group.add_argument('-c', '--config', action='store_true', default=False,
                           help='show the config of tool')
        group.add_argument('--download', action='store_true', default=False,
                           help='download tool files')
        group.add_argument('--clear', action='store_true', default=False,
                           help='clear tool files')
        group.add_argument('-d', '--daemon', action='store_true', default=False,
                           help='execute tools as a daemon')
        parser.add_argument('tool', nargs='...', choices=self._TOOL_NAMES)

    def _run(self, args: [str]) -> Optional[int]:
        args = self.argument_parser.parse_args(args)
        if len(args.tool) == 0 or args.tool[0] not in self._TOOL_NAMES:
            self.argument_parser.print_help()
            return -1

        tool_name = args.tool[0]
        tool_args = args.tool[1:]

        if args.config:
            logger.info(json.dumps(tools[tool_name].config, indent=2, ensure_ascii=False))
            return 0

        elif args.download:
            if not tools[tool_name].exists:
                tools[tool_name].prepare()
            logger.info(f"Download tool files success: {tools[tool_name].absolute_path}")
            return 0

        elif args.clear:
            tools[tool_name].clear()
            logger.info(f"Clear tool files success")
            return 0

        elif args.daemon:
            process = tools[tool_name].popen(
                *tool_args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return process.call_as_daemon()

        else:
            process = tools[tool_name].popen(*tool_args)
            return process.call()


command = Command()
if __name__ == "__main__":
    command.main()
