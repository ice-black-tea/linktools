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

from linktools import utils, resource, logger, ArgumentParser
from linktools.ios.device import Device, Usbmux, MuxError

_DEVICE_CACHE_PATH = resource.get_temp_path("ios_udid_cache.txt", create_parent=True)


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

            logger.info("more than one device/emulator")

            offset = 1
            for i in range(len(devices)):
                try:
                    name = Device(devices[0].udid, usbmux).name
                except Exception:
                    name = ""
                logger.info(f"%d: %-20s [%s]" % (i + offset, devices[i].udid, name))

            while True:
                offset = 1
                data = input(
                    "enter device index %d~%d (default %d): " %
                    (offset, len(devices) + offset - 1, offset)
                )
                if utils.is_empty(data):
                    return devices[0].udid
                index = utils.cast(int, data, offset - 1) - offset
                if 0 <= index < len(devices):
                    return devices[index].udid

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
