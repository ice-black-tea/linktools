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
import json
import sys
import time
from collections import OrderedDict

from android_tools.resource import resource
from android_tools.adb import Adb, Device
from android_tools.utils import Utils


class AdbArgumentParser(object):
    _global_options = [
        {"name": "-a", "nargs": 0},
        {"name": "-d", "nargs": 0},
        {"name": "-e", "nargs": 0},
        {"name": "-s", "nargs": 1},
        {"name": "-t", "nargs": 1},
        {"name": "-H", "nargs": 0},
        {"name": "-P", "nargs": 0},
        {"name": "-L", "nargs": 1},
    ]

    _global_custom_options = [
        {"name": "-i", "nargs": 1},  # custom option: -i index
        {"name": "-c", "nargs": 1},  # custom option: -c ip[:port]
        {"name": "-l", "nargs": 0},  # custom option: -l
    ]

    _general_commands = [
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
            option = self.match_options(argv[index], self._global_options)
            if option:
                start = index + 1
                end = index + option["nargs"] + 1
                index = end
                self.options[option["name"]] = argv[start:end]
                continue

            option = self.match_options(argv[index], self._global_custom_options)
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
        for command in self._general_commands:
            if self.command.startswith(command["name"]):
                return command
        return None


def load_last_options() -> dict:
    path = resource.get_store_path(".adb_config", create_file=True)
    try:
        with open(path, "r") as fd:
            return json.load(fd)
    except:
        return {}


def save_last_options(options: dict) -> None:
    path = resource.get_store_path(".adb_config", create_file=True)
    try:
        with open(path, "w+") as fd:
            json.dump(options, fd)
    except:
        pass


def adb_exec(parser: AdbArgumentParser):
    args = []
    save_last_options(parser.options)
    for option in parser.options:
        args.append(option)
        args.extend(parser.options[option])
    args.append(parser.command)
    args.extend(parser.argv)
    Adb.exec(*args, capture_output=False)


def extend_custom_options(parser: AdbArgumentParser) -> bool:
    options = parser.custom_options

    if Utils.is_contain(options, "-l"):
        last_options = load_last_options()
        for option in last_options:
            parser.options[option] = last_options[option]

    if Utils.is_contain(options, "-i"):
        devices = Adb.devices(alive=False)
        if Utils.is_empty(devices):
            print("error: no devices/emulators found", file=sys.stderr)
            return False
        index = Utils.get_item(options, "-i", 0, type=int, default=0)
        if not 0 < index <= len(devices):
            print("error: index %d out of range (%d ~ %d)" % (index, 1, len(devices)), file=sys.stderr)
            return False
        index = index - 1
        device = Utils.get_item(devices, index, default="")
        if not Utils.is_empty(device):
            parser.options["-s"] = [devices[index]]

    if Utils.is_contain(options, "-c"):
        connect = Utils.get_item(options, "-c", 0, type=str, default="")
        if Utils.is_empty(connect):
            print("error: unspecified ip[:port] ", file=sys.stderr)
            return False
        if connect.find(":") < 0:
            connect = connect + ":5555"
        devices = Adb.devices(alive=False)
        if connect not in devices:
            Adb.exec("connect", connect, capture_output=False)
            time.sleep(0.5)
        parser.options["-s"] = [connect]

    return True


def match_none_device(parser: AdbArgumentParser):
    adb_exec(parser)


def match_one_device(parser: AdbArgumentParser, device: str):
    parser.options["-s"] = [device]
    adb_exec(parser)


def match_some_devices(parser: AdbArgumentParser, devices: [str]):
    print("more than one device/emulator")
    for i in range(len(devices)):
        print("%-2d: %15s [%s]" % (i + 1, devices[i], Device(devices[i]).get_prop("ro.product.name")))
    while True:
        data = input("enter device index (%d ~ %d) [default 1]: " % (1, len(devices)))
        if Utils.is_empty(data):
            index = 1 - 1
            break
        index = Utils.cast(int, data, -1) - 1
        if 0 <= index < len(devices):
            break
    if index >= 0 or index < len(devices):
        parser.options["-s"] = [devices[index]]
    adb_exec(parser)


def main():
    parser = AdbArgumentParser()
    parser.parser(*sys.argv[1:])

    if not Utils.is_empty(parser.custom_options):
        if not extend_custom_options(parser):
            return

    if parser.is_general_command:
        adb_exec(parser)
        return

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
    try:
        main()
    except KeyboardInterrupt:
        pass
