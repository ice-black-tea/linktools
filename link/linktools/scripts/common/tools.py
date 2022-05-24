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

from linktools import ArgumentParser, tools, logger
from linktools.decorator import entry_point


@entry_point()
def main():
    tool_names = sorted([tool.name for tool in iter(tools)])

    parser = ArgumentParser(description='tools wrapper')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-c', '--config', action='store_true', default=False,
                       help='show the config of tool')
    group.add_argument('--download', action='store_true', default=False,
                       help='download tool files')
    group.add_argument('--clear', action='store_true', default=False,
                       help='clear tool files')
    group.add_argument('-d', '--daemon', action='store_true', default=False,
                       help='execute tools as a daemon')
    parser.add_argument('tool', nargs='...', choices=tool_names)

    args = parser.parse_args()
    if len(args.tool) == 0 or args.tool[0] not in tool_names:
        parser.print_help()
        exit(-1)

    tool_name = args.tool[0]
    tool_args = args.tool[1:]

    if args.config:
        logger.info(
            json.dumps(tools[tool_name].config, indent=2, ensure_ascii=False)
        )

    elif args.download:
        if not tools[tool_name].exists:
            tools[tool_name].prepare()
        logger.info(f"download tool files success: {tools[tool_name].absolute_path}")

    elif args.clear:
        tools[tool_name].clear()
        logger.info(f"clear tool files success")

    elif args.daemon:
        tools[tool_name].exec(
            *tool_args,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            daemon=True,
        )

    else:
        process, _, _ = tools[tool_name].exec(*tool_args)
        exit(process.returncode)


if __name__ == "__main__":
    main()
