#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : at_adb.py 
@time    : 2019/03/04
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

import sys
from collections import OrderedDict

from android_tools.adb import Adb
from android_tools.utils import Utils


class AdbArgumentParser(object):
    global_options = [
        {"name": "-a", "nargs": 0},
        {"name": "-d", "nargs": 0},
        {"name": "-e", "nargs": 0},
        {"name": "-s", "nargs": 1},
        {"name": "-t", "nargs": 1},
        {"name": "-H", "nargs": 0},
        {"name": "-P", "nargs": 0},
        {"name": "-L", "nargs": 1},
    ]

    global_custom_options = [
        {"name": "-i", "nargs": 1},  # custom option: -i index
        {"name": "-c", "nargs": 1},  # custom option: -i index
    ]

    general_commands = [
        {"name": "devices"},
        {"name": "help"},
        {"name": "version"},
        {"name": "connect"},
        {"name": "disconnect"},
        {"name": "keygen"},
        {"name": "wait-for-"},
        {"name": "start-server"},
        {"name": "kill-server"},
        {"name": "reconnect"},
    ]

    def __init__(self):
        self.options = OrderedDict()
        self.custom_options = OrderedDict()
        self.command = "help"
        self.argv = []

    def parser(self, *argv: [str]) -> None:
        if Utils.is_empty(argv):
            return

        index = 0
        while index < len(argv):
            option = self.match_options(argv[index], self.global_options)
            if option:
                start = index + 1
                end = index + option["nargs"] + 1
                index = end
                self.options[option["name"]] = argv[start:end]
                continue

            option = self.match_options(argv[index], self.global_custom_options)
            if option:
                start = index + 1
                end = index + option["nargs"] + 1
                index = end
                self.custom_options[option["name"]] = argv[start:end]
                continue

            self.command = argv[index]
            self.argv = argv[index + 1:]
            break

    @staticmethod
    def match_options(arg, options):
        for option in options:
            if arg == option["name"]:
                return option
        return None

    @property
    def is_general_command(self):
        for command in self.general_commands:
            if self.command.startswith(command["name"]):
                return command
        return None


def adb_exec(parser: AdbArgumentParser):
    args = []
    for option in parser.options:
        args.append(option)
        args.extend(parser.options[option])
    args.append(parser.command)
    args.extend(parser.argv)
    Adb.exec(*args, capture_output=False)


def extend_custom_options(parser: AdbArgumentParser):
    options = parser.custom_options

    index = Utils.get_item(options, "-i", 0, type=int, default=-1)
    if index >= 0:
        devices = Adb.devices(alive=False)
        index = index - 1
        if index >= len(devices):
            index = len(devices) - 1
        device = Utils.get_item(devices, index, default="")
        if not Utils.is_empty(device):
            parser.options["-s"] = [devices[index]]

    connect = Utils.get_item(options, "-c", 0, type=str, default=-1)
    if connect:
        devices = Adb.devices(alive=True)
        if connect not in devices:
            Adb.exec("connect", connect, capture_output=False)
        parser.options["-s"] = [connect]


def match_none_device(parser: AdbArgumentParser):
    adb_exec(parser)


def match_one_device(parser: AdbArgumentParser, device: str):
    parser.options["-s"] = [device]
    adb_exec(parser)


def match_some_devices(parser: AdbArgumentParser, devices: [str]):
    print("more than one device/emulator")
    for i in range(len(devices)):
        print("%-2d: %15s" % (i + 1, devices[i]))
    index = -1
    for i in range(5):
        data = input("enter device index [default 1]: ")
        if Utils.is_empty(data):
            index = 1 - 1
            break
        index = Utils.cast(int, data, -1) - 1
        if index >= 0 or index < len(devices):
            break
    if index >= 0 or index < len(devices):
        parser.options["-s"] = [devices[index]]
    adb_exec(parser)


def main():
    parser = AdbArgumentParser()
    parser.parser(*sys.argv[1:])

    if parser.is_general_command:
        adb_exec(parser)
        return

    if not Utils.is_empty(parser.custom_options):
        extend_custom_options(parser)

    if not Utils.is_empty(parser.options):
        adb_exec(parser)
        return

    devices = Adb.devices(alive=True)
    if len(devices) == 0:
        match_none_device(parser)
    elif len(devices) == 1:
        match_one_device(parser, next(iter(devices)))
    else:
        match_some_devices(parser, devices)


if __name__ == '__main__':
    main()
