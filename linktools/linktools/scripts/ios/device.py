#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Author    : HuJi <jihu.hj@alibaba-inc.com>
# Datetime  : 2022/2/27 12:40 AM
# User      : huji
# Product   : PyCharm
# Project   : link

from linktools import tools
from linktools.argparser.ios import IOSArgumentParser
from linktools.decorator import entry_point
from linktools.ios import MuxError


@entry_point(known_errors=(MuxError,))
def main():
    general_commands = [
        "version",
        "list",
        "parse",
        "watch",
        "wait-for-device",
    ]

    parser = IOSArgumentParser(description="tidevice wrapper")
    parser.add_argument('device_args', nargs='...', help="tidevice args")
    args, extra = parser.parse_known_args()

    device_args = [*extra, *args.device_args]
    if not extra:
        if args.device_args and args.device_args[0] not in general_commands:
            device = args.parse_device()
            device_args = ["--socket", device.usbmux.address, "-u", device.udid, *device_args]
            process = tools["tidevice"].popen(*device_args, capture_output=False)
            return process.call()

    process = tools["tidevice"].popen(*device_args, capture_output=False)
    return process.call()


if __name__ == '__main__':
    main()
