#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Datetime  : 2022/12/8 17:05
# Author    : HuJi <jihu.hj@alibaba-inc.com>

from argparse import ArgumentParser
from typing import Optional

from linktools import utils, cli


class Command(cli.IOSCommand):
    """
    OpenSSH secure file copy (require iOS device jailbreak)
    """

    _REMOTE_PATH_PREFIX = "@"

    def _add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("-u", "--user", action="store", default="root",
                            help="iOS ssh user (default: root)")
        parser.add_argument("-p", "--port", action="store", type=int, default=22,
                            help="iOS ssh port (default: 22)")
        parser.add_argument("-l", "--local-port", action="store", type=int, default=2222,
                            help="local listening port (default: 2222)")
        parser.add_argument("scp_args", nargs="...",
                            help=f"scp args, remote path needs to be prefixed with \"{self._REMOTE_PATH_PREFIX}\"")

    def _run(self, args: [str]) -> Optional[int]:
        args = self.argument_parser.parse_args(args)
        device = args.parse_device()

        scp_args = []
        for arg in args.scp_args:
            if arg.startswith(self._REMOTE_PATH_PREFIX):
                arg = f"{args.user}@127.0.0.1:{arg[len(self._REMOTE_PATH_PREFIX):]}"
            scp_args.append(arg)

        with device.forward(args.local_port, args.port):
            scp_args = [
                "scp", "-P", args.local_port,
                *scp_args
            ]
            return utils.Popen(*scp_args).call()


command = Command()
if __name__ == "__main__":
    command.main()
