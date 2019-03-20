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
import json
import sys
import time
import types

from android_tools.adb import Adb, AdbError, Device
from android_tools.resource import resource
from android_tools.utils import Utils
from .version import __version__


class ArgumentParser(argparse.ArgumentParser):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.add_argument("-v", "--version", action="version", version="%(prog)s " + __version__)


class AdbArgumentParser(ArgumentParser):

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        self._adb_parser = argparse.ArgumentParser()
        self._adb_group = self._adb_parser.add_argument_group(title="adb optional arguments")
        self._adb_group.add_argument("-s", metavar="serial", dest="adb_serial",
                                     help="use device with given serial (adb -s option)")
        self._adb_group.add_argument("-d", dest="adb_device", action="store_true",
                                     help="use USB device (adb -d option)")
        self._adb_group.add_argument("-e", dest="adb_emulator", action="store_true",
                                     help="use TCP/IP device (adb -e option)")
        self._adb_group.add_argument("-i", metavar="index", dest="adb_index", type=int,
                                     help="use device with given index")
        self._adb_group.add_argument("-c", metavar="ip[:port]", dest="adb_connect",
                                     help="use device with TCP/IP")
        self._adb_group.add_argument("-l", dest="adb_last", action="store_true",
                                     help="use last device")

        # noinspection PyProtectedMember
        self._adb_actions = self._adb_parser._actions
        # noinspection PyProtectedMember
        self._adb_option_string_actions = self._adb_parser._option_string_actions

    def parse_adb_args(self, args=None, namespace=None):
        if args is None:
            # args default to the system args
            args = sys.argv[1:]
        else:
            # make sure that args are mutable
            args = list(args)

        # default Namespace built from parser defaults
        if namespace is None:
            namespace = argparse.Namespace()

        # add any action defaults that aren"t present
        for action in self._adb_actions:
            if action.dest is not argparse.SUPPRESS:
                if not hasattr(namespace, action.dest):
                    if action.default is not argparse.SUPPRESS:
                        setattr(namespace, action.dest, action.default)

        # parse the arguments and exit if there are any errors
        option_string_indices = {}
        arg_string_pattern_parts = []
        arg_strings_iter = iter(args)
        for i, arg_string in enumerate(arg_strings_iter):

            # all args after -- are non-options
            if arg_string == '--':
                arg_string_pattern_parts.append('-')
                for arg_string in arg_strings_iter:
                    arg_string_pattern_parts.append('A')

            # otherwise, add the arg to the arg strings
            # and note the index if it was an option
            else:
                option_tuple = self._parse_optional(arg_string)
                if option_tuple is None:
                    pattern = 'A'
                else:
                    option_string_indices[i] = option_tuple
                    pattern = 'O'
                arg_string_pattern_parts.append(pattern)

        # join the pieces together to form the pattern
        arg_strings_pattern = ''.join(arg_string_pattern_parts)

        # parse adb arguments
        start_index = 0
        while start_index < len(args):
            arg_string = args[start_index]

            if '=' in arg_string:
                option_string, explicit_arg = arg_string.split('=', 1)
                action = Utils.get_item(self._adb_option_string_actions, option_string)
                if action not in self._adb_actions:
                    break
                start_index = start_index + 1
                action(self, namespace, explicit_arg)

            else:
                action = Utils.get_item(self._adb_option_string_actions, arg_string)
                if action not in self._adb_actions:
                    break
                start = start_index + 1
                selected_patterns = arg_strings_pattern[start:]
                arg_count = self._match_argument(action, selected_patterns)
                stop = start + arg_count
                start_index = stop
                action(self, namespace, self._get_values(action, args[start:stop]))

        def load_last_device():
            path = resource.get_store_path(".adb.device.config", create_file=True)
            try:
                with open(path, "rt") as fd:
                    return fd.read()
            except:
                return None

        def save_last_device(device):
            path = resource.get_store_path(".adb.device.config", create_file=True)
            try:
                with open(path, "wt+") as fd:
                    fd.write(device)
            except:
                pass

        def extend_adb_options(adb_options):
            if adb_options.adb_last:
                setattr(adb_options, "adb_serial", load_last_device())

            if adb_options.adb_index:
                devices = Adb.devices(alive=False)
                index = adb_options.adb_index
                if Utils.is_empty(devices):
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
                setattr(adb_options, "adb_serial", Adb.exec("-d", "get-serialno"))

            if adb_options.adb_emulator:
                setattr(adb_options, "adb_serial", Adb.exec("-e", "get-serialno"))

            if not adb_options.adb_serial:
                devices = Adb.devices(alive=True)
                if len(devices) == 0:
                    raise AdbError("error: no devices/emulators found")
                elif len(devices) == 1:
                    setattr(adb_options, "adb_serial", next(iter(devices)))
                else:
                    print("more than one device/emulator")
                    for i in range(len(devices)):
                        print("%d: %-20s [%s]" % (i + 1, devices[i], Device(devices[i]).get_prop("ro.product.name")))
                    while True:
                        data = input("enter device index (%d ~ %d) [default 1]: " % (1, len(devices)))
                        if Utils.is_empty(data):
                            index = 1 - 1
                            break
                        index = Utils.cast(int, data, -1) - 1
                        if 0 <= index < len(devices):
                            break
                    if index >= 0 or index < len(devices):
                        setattr(adb_options, "adb_serial", devices[index])

            save_last_device(adb_options.adb_serial)

            return adb_options.adb_serial

        setattr(namespace, "extend", types.MethodType(extend_adb_options, namespace))

        return namespace, args[start_index:]

    def format_help(self):
        self._action_groups.insert(2, self._adb_group)
        result = super().format_help()
        self._action_groups.remove(self._adb_group)
        return result
