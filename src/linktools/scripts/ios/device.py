#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Author    : HuJi <jihu.hj@alibaba-inc.com>
# Datetime  : 2022/2/27 12:40 AM
# User      : huji
# Product   : PyCharm
# Project   : link

from argparse import ArgumentParser
from typing import Optional

from linktools import utils, tools


class Script(utils.IOSScript):

    GENERAL_COMMANDS = [
        "version",
        "list",
        "parse",
        "watch",
        "wait-for-device",
    ]

    def _get_description(self) -> str:
        return "tidevice wrapper"

    def _add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument('device_args', nargs='...', help="tidevice args")

    def _run(self, args: [str]) -> Optional[int]:
        args, extra = self.argument_parser.parse_known_args(args)

        device_args = [*extra, *args.device_args]
        if not extra:
            if args.device_args and args.device_args[0] not in self.GENERAL_COMMANDS:
                device = args.parse_device()
                device_args = ["--socket", device.usbmux.address, "-u", device.udid, *device_args]
                process = tools["tidevice"].popen(*device_args, capture_output=False)
                return process.call()

        process = tools["tidevice"].popen(*device_args, capture_output=False)
        return process.call()


script = Script()
if __name__ == '__main__':
    script.main()
