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

from linktools import utils, resource, logger
from linktools.android.adb import Adb, AdbError, Device
from linktools.argparser import ArgumentParser

_ADB_SERIAL_CACHE_PATH = resource.get_data_path("adb_serial_cache.txt")


class AdbArgumentParser(ArgumentParser):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        group = self.add_argument_group(title="adb optional arguments").add_mutually_exclusive_group()
        group.add_argument("-s", "--serial", metavar="serial", dest="parse_adb_serial", action=_AdbSerialAction,
                           help="use device with given serial (adb -s option)", default=_parse_adb_serial)
        group.add_argument("-d", "--device", dest="parse_adb_serial", nargs=0, const=True, action=_AdbDeviceAction,
                           help="use USB device (adb -d option)")
        group.add_argument("-e", "--emulator", dest="parse_adb_serial", nargs=0, const=True, action=_AdbEmulatorAction,
                           help="use TCP/IP device (adb -e option)")
        group.add_argument("-i", "--index", metavar="index", dest="parse_adb_serial", action=_AdbIndexAction,
                           help="use device with given index")
        group.add_argument("-c", "--connect", metavar="ip[:port]", dest="parse_adb_serial", action=_AdbConnectAction,
                           help="use device with TCP/IP")
        group.add_argument("-l", "--last", dest="parse_adb_serial", nargs=0, const=True, action=_AdbLastAction,
                           help="use last device")


def _parse_handler(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        serial = fn(*args, **kwargs)
        if serial is not None:
            with open(_ADB_SERIAL_CACHE_PATH, "wt+") as fd:
                fd.write(serial)
        return serial

    return wrapper


@_parse_handler
def _parse_adb_serial():
    devices = Adb.devices(alive=True)

    if len(devices) == 0:
        raise AdbError("error: no devices/emulators found")

    if len(devices) == 1:
        return devices[0]

    logger.message("more than one device/emulator")
    for i in range(len(devices)):
        try:
            name = Device(devices[i]).get_prop("ro.product.name", timeout=1)
        except Exception:
            name = ""
        logger.message("%d: %-20s [%s]" % (i + 1, devices[i], name))
    while True:
        offset = 1
        data = input("enter device index (%d ~ %d) [default 1]: " % (1, len(devices)))
        if utils.is_empty(data):
            index = 1 - offset
            break
        index = utils.cast(int, data, -1) - offset
        if 0 <= index < len(devices):
            break
    if 0 <= index < len(devices):
        return devices[index]


class _AdbSerialAction(argparse.Action):

    def __call__(self, parser, namespace, values, option_string=None):
        @_parse_handler
        def wrapper():
            return str(values)

        setattr(namespace, self.dest, wrapper)


class _AdbDeviceAction(argparse.Action):

    def __call__(self, parser, namespace, values, option_string=None):
        @_parse_handler
        def wrapper():
            return Adb.exec("-d", "get-serialno").strip(" \r\n")

        setattr(namespace, self.dest, wrapper)


class _AdbEmulatorAction(argparse.Action):

    def __call__(self, parser, namespace, values, option_string=None):
        @_parse_handler
        def wrapper():
            return Adb.exec("-e", "get-serialno").strip(" \r\n")

        setattr(namespace, self.dest, wrapper)


class _AdbIndexAction(argparse.Action):

    def __call__(self, parser, namespace, values, option_string=None):
        @_parse_handler
        def wrapper():
            index = int(values)
            devices = Adb.devices(alive=True)
            if utils.is_empty(devices):
                raise AdbError("error: no devices/emulators found")
            if not 0 < index <= len(devices):
                raise AdbError("error: index %d out of range (%d ~ %d)" % (index, 1, len(devices)))
            index = index - 1
            return devices[index]

        setattr(namespace, self.dest, wrapper)


class _AdbConnectAction(argparse.Action):

    def __call__(self, parser, namespace, values, option_string=None):
        @_parse_handler
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


class _AdbLastAction(argparse.Action):

    def __call__(self, parser, namespace, values, option_string=None):
        @_parse_handler
        def wrapper():
            if os.path.exists(_ADB_SERIAL_CACHE_PATH):
                with open(_ADB_SERIAL_CACHE_PATH, "rt") as fd:
                    result = fd.read().strip()
                    if len(result) > 0:
                        return result
            raise AdbError("error: no device used last time")

        setattr(namespace, self.dest, wrapper)
