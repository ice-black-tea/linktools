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

from linktools import utils, resource, logger
from linktools.android.adb import Adb, AdbError, Device
from linktools.argparser import ArgumentParser


class AdbArgumentParser(ArgumentParser):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self._adb_group = self.add_argument_group(title="adb optional arguments")
        group = self._adb_group.add_mutually_exclusive_group()
        group.add_argument("-s", "--serial", metavar="serial", dest="adb_serial",
                           help="use device with given serial (adb -s option)")
        group.add_argument("-d", "--device", dest="adb_device", action="store_true",
                           help="use USB device (adb -d option)")
        group.add_argument("-e", "--emulator", dest="adb_emulator", action="store_true",
                           help="use TCP/IP device (adb -e option)")
        group.add_argument("-i", "--index", metavar="index", dest="adb_index", type=int,
                           help="use device with given index")
        group.add_argument("-c", "--connect", metavar="ip[:port]", dest="adb_connect",
                           help="use device with TCP/IP")
        group.add_argument("-l", "--last", dest="adb_last", action="store_true",
                           help="use last device")

    def _parse_known_args(self, arg_strings, namespace):
        namespace, extras = super()._parse_known_args(arg_strings, namespace)
        return _NamespaceWrapper(namespace), extras


class _NamespaceWrapper:

    def __init__(self, namespace):
        self.namespace = namespace

    def __getattr__(self, name):
        return getattr(self.namespace, name)

    def __str__(self):
        return self.namespace.__str__()

    def load_last_device(self):
        path = resource.get_cache_path("adb_device.txt", create_file=True)
        try:
            with open(path, "rt") as fd:
                return fd.read()
        except:
            return None

    def save_last_device(self, device):
        path = resource.get_cache_path("adb_device.txt", create_file=True)
        try:
            with open(path, "wt+") as fd:
                fd.write(device)
        except:
            pass

    def parse_adb_serial(self):
        if self.adb_last:
            setattr(self, "adb_serial", self.load_last_device())

        if self.adb_index:
            devices = Adb.devices(alive=False)
            index = self.adb_index
            if utils.is_empty(devices):
                raise AdbError("error: no devices/emulators found")
            if not 0 < index <= len(devices):
                raise AdbError("error: index %d out of range (%d ~ %d)" % (index, 1, len(devices)))
            index = index - 1
            setattr(self, "adb_serial", devices[index])

        if self.adb_connect:
            addr = self.adb_connect
            if addr.find(":") < 0:
                addr = addr + ":5555"
            devices = Adb.devices(alive=False)
            if addr not in devices:
                process = Adb.popen("connect", addr, capture_output=False)
                process.wait()
            setattr(self, "adb_serial", addr)

        if self.adb_device:
            setattr(self, "adb_serial", Adb.exec("-d", "get-serialno").strip(" \r\n"))

        if self.adb_emulator:
            setattr(self, "adb_serial", Adb.exec("-e", "get-serialno").strip(" \r\n"))

        if not self.adb_serial:
            devices = Adb.devices(alive=True)
            if len(devices) == 0:
                raise AdbError("error: no devices/emulators found")
            elif len(devices) == 1:
                setattr(self, "adb_serial", next(iter(devices)))
            else:
                logger.info("more than one device/emulator")
                for i in range(len(devices)):
                    try:
                        name = Device(devices[i]).get_prop("ro.product.name")
                    except:
                        name = ""
                    logger.info("%d: %-20s [%s]" % (i + 1, devices[i], name))
                while True:
                    data = input("enter device index (%d ~ %d) [default 1]: " % (1, len(devices)))
                    if utils.is_empty(data):
                        index = 1 - 1
                        break
                    index = utils.cast(int, data, -1) - 1
                    if 0 <= index < len(devices):
                        break
                if index >= 0 or index < len(devices):
                    setattr(self, "adb_serial", devices[index])

        self.save_last_device(self.adb_serial)

        return self.adb_serial
