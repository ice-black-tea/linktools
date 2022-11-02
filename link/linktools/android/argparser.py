#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : argparser.py 
@time    : 2019/03/09
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
import argparse
import functools
import os

from rich import get_console
from rich.prompt import IntPrompt
from rich.table import Table

from linktools import utils, resource, ArgumentParser
from linktools.android.adb import Adb, AdbError, Device

_DEVICE_CACHE_PATH = resource.get_temp_path("cache", "device", "android", create_parent=True)


class AndroidArgumentParser(ArgumentParser):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        def parse_handler(fn):
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                serial = fn(*args, **kwargs)
                if serial is not None:
                    with open(_DEVICE_CACHE_PATH, "wt+") as fd:
                        fd.write(serial)
                return Device(serial)

            return wrapper

        @parse_handler
        def parse_device():
            devices = Adb.devices(alive=True)

            if len(devices) == 0:
                raise AdbError("no devices/emulators found")

            if len(devices) == 1:
                return devices[0]

            table = Table()
            table.add_column("Index", justify="right", style="cyan", no_wrap=True)
            table.add_column("Serial", style="magenta")
            table.add_column("Name", style="magenta")

            offset = 1
            for i in range(len(devices)):
                try:
                    name = Device(devices[i]).get_prop("ro.product.name", timeout=1)
                except:
                    name = ""
                table.add_row(str(i + offset), devices[i], name)

            console = get_console()
            console.print(table)

            prompt = f"More than one device/emulator. {os.linesep}" \
                     f"Enter device index"
            choices = [str(i) for i in range(offset, len(devices) + offset, 1)]
            index = IntPrompt.ask(prompt, choices=choices, default=offset, console=console)

            return devices[index - offset]

        class SerialAction(argparse.Action):

            def __call__(self, parser, namespace, values, option_string=None):
                @parse_handler
                def wrapper():
                    return str(values)

                setattr(namespace, self.dest, wrapper)

        class DeviceAction(argparse.Action):

            def __call__(self, parser, namespace, values, option_string=None):
                @parse_handler
                def wrapper():
                    return Adb.exec("-d", "get-serialno").strip(" \r\n")

                setattr(namespace, self.dest, wrapper)

        class EmulatorAction(argparse.Action):

            def __call__(self, parser, namespace, values, option_string=None):
                @parse_handler
                def wrapper():
                    return Adb.exec("-e", "get-serialno").strip(" \r\n")

                setattr(namespace, self.dest, wrapper)

        class IndexAction(argparse.Action):

            def __call__(self, parser, namespace, values, option_string=None):
                @parse_handler
                def wrapper():
                    index = int(values)
                    devices = Adb.devices(alive=True)
                    if utils.is_empty(devices):
                        raise AdbError("no devices/emulators found")
                    if not 0 < index <= len(devices):
                        raise AdbError("index %d out of range %d~%d" % (index, 1, len(devices)))
                    index = index - 1
                    return devices[index]

                setattr(namespace, self.dest, wrapper)

        class ConnectAction(argparse.Action):

            def __call__(self, parser, namespace, values, option_string=None):
                @parse_handler
                def wrapper():
                    addr = str(values)
                    if addr.find(":") < 0:
                        addr = addr + ":5555"
                    devices = Adb.devices()
                    if addr not in devices:
                        process = Adb.popen("connect", addr, capture_output=False)
                        process.wait()
                    return addr

                setattr(namespace, self.dest, wrapper)

        class LastAction(argparse.Action):

            def __call__(self, parser, namespace, values, option_string=None):
                @parse_handler
                def wrapper():
                    if os.path.exists(_DEVICE_CACHE_PATH):
                        with open(_DEVICE_CACHE_PATH, "rt") as fd:
                            result = fd.read().strip()
                            if len(result) > 0:
                                return result
                    raise AdbError("no device used last time")

                setattr(namespace, self.dest, wrapper)

        group = self.add_argument_group(title="adb optional arguments").add_mutually_exclusive_group()
        group.add_argument("-s", "--serial", metavar="SERIAL", dest="parse_device", action=SerialAction,
                           help="use device with given serial (adb -s option)", default=parse_device)
        group.add_argument("-d", "--device", dest="parse_device", nargs=0, const=True, action=DeviceAction,
                           help="use USB device (adb -d option)")
        group.add_argument("-e", "--emulator", dest="parse_device", nargs=0, const=True, action=EmulatorAction,
                           help="use TCP/IP device (adb -e option)")
        group.add_argument("-i", "--index", metavar="INDEX", dest="parse_device", action=IndexAction,
                           help="use device with given index")
        group.add_argument("-c", "--connect", metavar="IP[:PORT]", dest="parse_device", action=ConnectAction,
                           help="use device with TCP/IP")
        group.add_argument("-l", "--last", dest="parse_device", nargs=0, const=True, action=LastAction,
                           help="use last device")
