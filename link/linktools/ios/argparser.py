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
from linktools.ios.device import Device, Usbmux, MuxError

_DEVICE_CACHE_PATH = resource.get_temp_path("cache", "device", "ios", create_parent=True)


class IOSArgumentParser(ArgumentParser):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        def parse_handler(fn):
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                udid = fn(*args, **kwargs)
                if udid is not None:
                    with open(_DEVICE_CACHE_PATH, "wt+") as fd:
                        fd.write(udid)
                return Device(udid)

            return wrapper

        @parse_handler
        def parse_device():
            usbmux = Usbmux.get_default()
            devices = usbmux.device_list()
            if len(devices) == 0:
                raise MuxError("no devices/emulators found")

            if len(devices) == 1:
                return devices[0].udid

            table = Table()
            table.add_column("Index", justify="right", style="cyan", no_wrap=True)
            table.add_column("UDID", style="magenta")
            table.add_column("Name", style="magenta")

            offset = 1
            for i in range(len(devices)):
                try:
                    udid = devices[i].udid
                    name = Device(devices[0].udid, usbmux).name
                except Exception:
                    udid = ""
                    name = ""
                table.add_row(str(i + offset), udid, name)

            console = get_console()
            console.print(table)

            prompt = f"More than one device/emulator. {os.linesep}" \
                     f"Enter device index"
            choices = [str(i) for i in range(offset, len(devices) + offset, 1)]
            index = IntPrompt.ask(prompt, choices=choices, default=offset, console=console)

            return devices[index - offset].udid

        class UdidAction(argparse.Action):

            def __call__(self, parser, namespace, values, option_string=None):
                @parse_handler
                def wrapper():
                    return str(values)

                setattr(namespace, self.dest, wrapper)

        class IndexAction(argparse.Action):

            def __call__(self, parser, namespace, values, option_string=None):
                @parse_handler
                def wrapper():
                    index = int(values)
                    usbmux = Usbmux.get_default()
                    devices = usbmux.device_list()
                    if utils.is_empty(devices):
                        raise MuxError("no devices/emulators found")
                    if not 0 < index <= len(devices):
                        raise MuxError("index %d out of range %d~%d" % (index, 1, len(devices)))
                    index = index - 1
                    return devices[index].udid

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
                    raise MuxError("no device used last time")

                setattr(namespace, self.dest, wrapper)

        class UsbmuxdAction(argparse.Action):

            def __call__(self, parser, namespace, values, option_string=None):
                Usbmux.set_default(Usbmux(str(values)))

        group = self.add_argument_group(title="device optional arguments")
        _group = group.add_mutually_exclusive_group()
        _group.add_argument("-u", "--udid", metavar="UDID", dest="parse_device", action=UdidAction,
                            help="specify unique device identifier", default=parse_device)
        _group.add_argument("-i", "--index", metavar="INDEX", dest="parse_device", action=IndexAction,
                            help="use device with given index")
        _group.add_argument("-l", "--last", dest="parse_device", nargs=0, const=True, action=LastAction,
                            help="use last device")
        group.add_argument("--socket", metavar="SOCKET", action=UsbmuxdAction,
                           help="usbmuxd listen address, host:port or local-path")
