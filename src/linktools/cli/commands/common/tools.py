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
from typing import Optional, Type, List

from linktools import ToolError
from linktools.cli import BaseCommand
from linktools.cli.argparse import KeyValueAction
from linktools.utils import DownloadError


class Command(BaseCommand):
    """
    Download and use tools
    """

    @property
    def known_errors(self) -> List[Type[BaseException]]:
        return super().known_errors + [ToolError, DownloadError]

    def init_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("--set", action=KeyValueAction, nargs=1, dest="configs", default={},
                            help="set the config of tool")

        group = parser.add_mutually_exclusive_group()
        group.add_argument("-c", "--config", action="store_true", default=False,
                           help="show the config of tool")
        group.add_argument("--download", action="store_true", default=False,
                           help="download tool files")
        group.add_argument("--clear", action="store_true", default=False,
                           help="clear tool files")
        group.add_argument("-d", "--daemon", action="store_true", default=False,
                           help="execute tools as a daemon")

        subparsers = parser.add_subparsers(title="tool arguments")
        for name in sorted([tool.name for tool in iter(self.environ.tools)]):
            tool_parser = subparsers.add_parser(name, prefix_chars=chr(0))
            tool_parser.add_argument("args", nargs="...")
            tool_parser.set_defaults(tool=name)

    def run(self, args: [str]) -> Optional[int]:
        args = self.parse_args(args)
        if not hasattr(args, "tool") or not args.tool:
            self.print_help()
            return -1

        tool_name = args.tool
        tool_args = args.args

        tool = self.environ.get_tool(tool_name, **args.configs)

        if args.config:
            self.logger.info(json.dumps(tool.config, indent=2, ensure_ascii=False))
            return 0

        elif args.download:
            if not tool.exists:
                tool.prepare()
            self.logger.info(f"Download tool files success: {tool.absolute_path}")
            return 0

        elif args.clear:
            tool.clear()
            self.logger.info(f"Clear tool files success")
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
