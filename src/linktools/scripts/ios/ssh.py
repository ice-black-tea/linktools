#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : ssh.py 
@time    : 2022/11/27
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


class Script(utils.IOSScript):

    @property
    def _description(self) -> str:
        return "OpenSSH remote login client (iOS device need jailbreak)"

    def _add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("-u", "--user", action="store", default="root",
                            help="iOS ssh user (default: root)")
        parser.add_argument("-p", "--port", action="store", type=int, default=22,
                            help="iOS ssh port (default: 22)")
        parser.add_argument("-l", "--local-port", action="store", type=int, default=2222,
                            help="local listening port (default: 2222)")
        parser.add_argument('ssh_args', nargs='...', help="ssh args")

    def _run(self, args: [str]) -> Optional[int]:
        args = self.argument_parser.parse_args(args)
        device = args.parse_device()

        with device.forward(args.local_port, args.port):
            ssh_args = [
                "ssh", f"{args.user}@127.0.0.1",
                "-p", args.local_port,
                *args.ssh_args
            ]
            return utils.Popen(*ssh_args).call()


script = Script()
if __name__ == '__main__':
    script.main()
