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

    def add_arguments(self, parser: ArgumentParser) -> None:
        group = parser.add_mutually_exclusive_group()
        parser.add_argument("--set", metavar=("KEY", "VALUE"),
                            action="append", nargs=2, dest="configs", default=[],
                            help="set the config of tool")
        group.add_argument("-c", "--config", action="store_true", default=False,
                           help="show the config of tool")
        group.add_argument("--download", action="store_true", default=False,
                           help="download tool files")
        group.add_argument("--clear", action="store_true", default=False,
                           help="clear tool files")
        group.add_argument("-d", "--daemon", action="store_true", default=False,
                           help="execute tools as a daemon")
        parser.add_argument("tool", nargs="...", choices=self._TOOL_NAMES)

    def run(self, args: [str]) -> Optional[int]:
        args = self.argument_parser.parse_args(args)
        if len(args.tool) == 0 or args.tool[0] not in self._TOOL_NAMES:
            self.argument_parser.print_help()
            return -1

        tool_name = args.tool[0]
        tool_args = args.tool[1:]
        tool = tools[tool_name].copy(**{k: v for k, v in args.configs})

        if args.config:
            logger.info(json.dumps(tool.config, indent=2, ensure_ascii=False))
            return 0

        elif args.download:
            if not tool.exists:
                tool.prepare()
            logger.info(f"Download tool files success: {tool.absolute_path}")
            return 0

        elif args.clear:
            tool.clear()
            logger.info(f"Clear tool files success")
            return 0

        elif args.daemon:
            process = tool.popen(
                *tool_args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return process.call_as_daemon()

        else:
            process = tool.popen(*tool_args)
            return process.call()


command = Command()
if __name__ == "__main__":
    command.main()
