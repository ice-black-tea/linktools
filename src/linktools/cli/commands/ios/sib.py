#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from argparse import ArgumentParser
from typing import Optional

from linktools import cli
from linktools.ios import Sib


class Command(cli.IOSCommand):
    """
    Sib that supports multiple devices
    """

    _GENERAL_COMMANDS = [
        "completion",
        "devices",
        "help",
        "version",
        "remote",
    ]

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument('sib_args', nargs='...', help="sib args")

    def run(self, args: [str]) -> Optional[int]:
        args, extra = self.argument_parser.parse_known_args(args)

        sib_args = [*extra, *args.sib_args]
        if not extra:
            if args.sib_args and args.sib_args[0] not in self._GENERAL_COMMANDS:
                device = args.parse_device()
                process = device.popen(*sib_args, capture_output=False)
                return process.call()

        process = Sib.popen(*sib_args, capture_output=False)
        return process.call()


command = Command()
if __name__ == "__main__":
    command.main()
