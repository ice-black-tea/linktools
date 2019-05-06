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
import time
import types

from .adb import Adb, AdbError, Device
from .resource import resource
from .utils import utils
from .version import __version__


class ArgumentParser(argparse.ArgumentParser):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.add_argument("-v", "--version", action="version", version="%(prog)s " + __version__)


class AdbArgumentParser(ArgumentParser):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self._adb_group = self.add_argument_group(title="adb optional arguments")
        group = self._adb_group.add_mutually_exclusive_group()
        group.add_argument("-s", metavar="serial", dest="adb_serial",
                           help="use device with given serial (adb -s option)")
        group.add_argument("-d", dest="adb_device", action="store_true",
                           help="use USB device (adb -d option)")
        group.add_argument("-e", dest="adb_emulator", action="store_true",
                           help="use TCP/IP device (adb -e option)")
        group.add_argument("-i", metavar="index", dest="adb_index", type=int,
                           help="use device with given index")
        group.add_argument("-c", metavar="ip[:port]", dest="adb_connect",
                           help="use device with TCP/IP")
        group.add_argument("-l", dest="adb_last", action="store_true",
                           help="use last device")

    def _parse_known_args(self, arg_strings, namespace):
        namespace, extras = super()._parse_known_args(arg_strings, namespace)

        def load_last_device():
            path = resource.get_storage_path("adb_device.txt", create_file=True)
            try:
                with open(path, "rt") as fd:
                    return fd.read()
            except:
                return None

        def save_last_device(device):
            path = resource.get_storage_path("adb_device.txt", create_file=True)
            try:
                with open(path, "wt+") as fd:
                    fd.write(device)
            except:
                pass

        def parse_adb_serial(adb_options):
            if adb_options.adb_last:
                setattr(adb_options, "adb_serial", load_last_device())

            if adb_options.adb_index:
                devices = Adb.devices(alive=False)
                index = adb_options.adb_index
                if utils.is_empty(devices):
                    raise AdbError("error: no devices/emulators found")
                if not 0 < index <= len(devices):
                    raise AdbError("error: index %d out of range (%d ~ %d)" % (index, 1, len(devices)))
                index = index - 1
                setattr(adb_options, "adb_serial", devices[index])

            if adb_options.adb_connect:
                addr = adb_options.adb_connect
                if addr.find(":") < 0:
                    addr = addr + ":5555"
                devices = Adb.devices(alive=False)
                if addr not in devices:
                    Adb.exec("connect", addr, capture_output=False)
                    time.sleep(0.5)
                setattr(adb_options, "adb_serial", addr)

            if adb_options.adb_device:
                setattr(adb_options, "adb_serial", Adb.exec("-d", "get-serialno").strip(" \r\n"))

            if adb_options.adb_emulator:
                setattr(adb_options, "adb_serial", Adb.exec("-e", "get-serialno").strip(" \r\n"))

            if not adb_options.adb_serial:
                devices = Adb.devices(alive=True)
                if len(devices) == 0:
                    raise AdbError("error: no devices/emulators found")
                elif len(devices) == 1:
                    setattr(adb_options, "adb_serial", next(iter(devices)))
                else:
                    print("more than one device/emulator")
                    for i in range(len(devices)):
                        try:
                            name = Device(devices[i]).get_prop("ro.product.name")
                        except:
                            name = ""
                        print("%d: %-20s [%s]" % (i + 1, devices[i], name))
                    while True:
                        data = input("enter device index (%d ~ %d) [default 1]: " % (1, len(devices)))
                        if utils.is_empty(data):
                            index = 1 - 1
                            break
                        index = utils.cast(int, data, -1) - 1
                        if 0 <= index < len(devices):
                            break
                    if index >= 0 or index < len(devices):
                        setattr(adb_options, "adb_serial", devices[index])

            save_last_device(adb_options.adb_serial)

            return adb_options.adb_serial

        setattr(namespace, "parse_adb_serial", types.MethodType(parse_adb_serial, namespace))

        return namespace, extras
