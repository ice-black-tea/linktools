#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from argparse import ArgumentParser, Namespace
from typing import Optional

from linktools.cli import IOSCommand


class Command(IOSCommand):
    """
    Manage multiple iOS devices effortlessly with sib commands
    """

    _GENERAL_COMMANDS = [
        "completion",
        "devices",
        "help",
        "version",
        "remote",
    ]

    def main(self, *args, **kwargs) -> None:
        self.environ.config.set("SHOW_LOG_LEVEL", False)
        self.environ.config.set("SHOW_LOG_TIME", False)
        return super().main(*args, **kwargs)

    def init_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument('sib_args', nargs='...', metavar="args", help="sib args")

    def run(self, args: Namespace) -> Optional[int]:
        if args.sib_args and args.sib_args[0] not in self._GENERAL_COMMANDS:
            device = args.device_picker.pick()
            process = device.popen(*args.sib_args, capture_output=False)
            return process.call()

        sib = args.device_picker.bridge
        process = sib.popen(*args.sib_args, capture_output=False)
        return process.call()


command = Command()
if __name__ == "__main__":
    command.main()
