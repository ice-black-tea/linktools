#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : __main__.py 
@time    : 2022/12/13
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

from .cli import BaseCommand, commands, SubCommandError


class Command(BaseCommand):

    def __init__(self):
        self.subcommands = list(self.walk_subcommands(commands))

    def init_arguments(self, parser: ArgumentParser) -> None:
        self.add_subcommands(parser=parser, target=self.subcommands)

    def run(self, args: Namespace) -> Optional[int]:
        try:
            return self.run_subcommand(args)
        except SubCommandError:
            return self.print_subcommands(self.subcommands)


command = Command()
if __name__ == '__main__':
    command.main()
