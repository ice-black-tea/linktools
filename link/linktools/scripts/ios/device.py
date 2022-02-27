#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Author    : HuJi <jihu.hj@alibaba-inc.com>
# Datetime  : 2022/2/27 12:40 AM
# User      : huji
# Product   : PyCharm
# Project   : link

from linktools import tools
from linktools.decorator import entry_point
from linktools.ios import MuxError, IOSArgumentParser


@entry_point(known_errors=[MuxError])
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
    if len(device_args) == 0:
        process = tools["tidevice"].popen(capture_output=False)
        process.communicate()
        return process.returncode

    # 如果第一个不是"-"开头的参数，并且参数需要添加设备，就额外添加"-s serial"参数
    if not device_args[0].startswith("-"):
        if device_args[0] not in general_commands:
            device = args.parse_device()
            device_args = ["--socket", device.usbmux.address, "-u", device.udid, *device_args]
            tools["tidevice"].exec(*device_args, capture_output=False)
            return

    tools["tidevice"].exec(*device_args, capture_output=False)


if __name__ == '__main__':
    main()
