#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : entry.py 
@time    : 2022/12/18
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

import abc
import functools
import logging
import os
import sys
import traceback
from abc import ABC
from argparse import ArgumentParser, Action, SUPPRESS
from typing import Tuple, Type, Optional

from rich import get_console
from rich.prompt import IntPrompt
from rich.table import Table

from ._utils import ignore_error
from .._environ import environ
from .._logging import LogHandler, get_logger
from ..decorator import cached_property
from ..version import __version__


class ConsoleScript(abc.ABC):
    logger: logging.Logger = cached_property(lambda self: self._get_logger())
    description: str = cached_property(lambda self: self._get_description())
    argument_parser: ArgumentParser = cached_property(lambda self: self._create_argument_parser())
    known_errors: Tuple[Type[BaseException]] = cached_property(lambda self: self._get_known_errors())

    def main(self, *args, **kwargs):
        logging.basicConfig(
            level=logging.INFO,
            format="%(message)s",
            datefmt="[%X]",
            handlers=[LogHandler()]
        )
        self._exit(
            self.run(*args, **kwargs)
        )

    def _get_logger(self) -> logging.Logger:
        return get_logger()

    @abc.abstractmethod
    def _get_description(self) -> str:
        pass

    def _get_known_errors(self) -> Tuple[Type[BaseException]]:
        return tuple()

    @abc.abstractmethod
    def _add_arguments(self, parser: ArgumentParser) -> None:
        pass

    @abc.abstractmethod
    def _run(self, args: [str]) -> Optional[int]:
        pass

    def _exit(self, exit_code: int):
        exit(exit_code)

    def run(self, args: [str] = None) -> int:
        try:
            args = args or sys.argv[1:]
            exit_code = self._run(args) or 0

        except SystemExit as e:
            exit_code = e.code

        except (KeyboardInterrupt, EOFError, *self.known_errors) as e:
            exit_code = 1
            error_type, error_message = e.__class__.__name__, str(e).strip()
            self.logger.error(f"{error_type}: {error_message}" if error_message else error_type)

        except:
            exit_code = 1
            if environ.debug:
                console = get_console()
                console.print_exception(show_locals=True)
            else:
                self.logger.error(traceback.format_exc())

        return exit_code

    def _create_argument_parser(self):
        parser = ArgumentParser(description=self.description, conflict_handler="resolve")
        self._add_base_arguments(parser)
        self._add_arguments(parser)
        return parser

    def _add_base_arguments(self, parser: ArgumentParser):
        class VerboseAction(Action):

            def __init__(self,
                         option_strings,
                         dest=SUPPRESS,
                         default=SUPPRESS,
                         help=None):
                super(VerboseAction, self).__init__(
                    option_strings=option_strings,
                    dest=dest,
                    default=default,
                    nargs=0,
                    help=help)

            def __call__(self, parser, namespace, values, option_string=None):
                environ.logger.setLevel(logging.DEBUG)

        class DebugAction(Action):

            def __init__(self,
                         option_strings,
                         dest=SUPPRESS,
                         default=SUPPRESS,
                         help=None):
                super(DebugAction, self).__init__(
                    option_strings=option_strings,
                    dest=dest,
                    default=default,
                    nargs=0,
                    help=help)

            def __call__(self, parser, namespace, values, option_string=None):
                environ.debug = True
                environ.logger.setLevel(logging.DEBUG)

        parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
        parser.add_argument("-v", "--verbose", action=VerboseAction, help="increase log verbosity")
        parser.add_argument("-d", "--debug", action=DebugAction, help="enable debug mode and increase log verbosity")


class AndroidScript(ConsoleScript, ABC):

    def _get_known_errors(self) -> Tuple[Type[BaseException]]:
        from linktools.android import AdbError
        return AdbError,

    def _add_base_arguments(self, parser: ArgumentParser):
        super()._add_base_arguments(parser)

        from linktools.android import Adb, Device, AdbError

        cache_path = environ.resource.get_temp_path("cache", "device", "android", create_parent=True)

        def parse_handler(fn):
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                device = fn(*args, **kwargs)
                if device is not None:
                    with open(cache_path, "wt+") as fd:
                        fd.write(device.id)
                return device

            return wrapper

        @parse_handler
        def parse_device():
            devices = Adb.devices(alive=True)
            if len(devices) == 0:
                raise AdbError("no devices/emulators found")

            if len(devices) == 1:
                return devices[0]

            table = Table(show_lines=True)
            table.add_column("Index", justify="right", style="cyan", no_wrap=True)
            table.add_column("Serial", style="magenta")
            table.add_column("Model", style="magenta")

            offset = 1
            for i in range(len(devices)):
                table.add_row(
                    str(i + offset),
                    devices[i].id,
                    ignore_error(lambda: devices[i].get_prop("ro.product.model", timeout=1)) or "",
                )

            console = get_console()
            console.print(table)

            prompt = f"More than one device/emulator. {os.linesep}" \
                     f"Enter device index"
            choices = [str(i) for i in range(offset, len(devices) + offset, 1)]
            index = IntPrompt.ask(prompt, choices=choices, default=offset, console=console)

            return devices[index - offset]

        class SerialAction(Action):

            def __call__(self, parser, namespace, values, option_string=None):
                @parse_handler
                def wrapper():
                    return Device(str(values))

                setattr(namespace, self.dest, wrapper)

        class DeviceAction(Action):

            def __call__(self, parser, namespace, values, option_string=None):
                @parse_handler
                def wrapper():
                    return Device(Adb.exec("-d", "get-serialno").strip(" \r\n"))

                setattr(namespace, self.dest, wrapper)

        class EmulatorAction(Action):

            def __call__(self, parser, namespace, values, option_string=None):
                @parse_handler
                def wrapper():
                    return Device(Adb.exec("-e", "get-serialno").strip(" \r\n"))

                setattr(namespace, self.dest, wrapper)

        class ConnectAction(Action):

            def __call__(self, parser, namespace, values, option_string=None):
                @parse_handler
                def wrapper():
                    addr = str(values)
                    if addr.find(":") < 0:
                        addr = addr + ":5555"
                    devices = Adb.devices()
                    if addr not in [device.id for device in devices]:
                        Adb.exec("connect", addr, output_to_logger=True)
                    return Device(addr)

                setattr(namespace, self.dest, wrapper)

        class LastAction(Action):

            def __call__(self, parser, namespace, values, option_string=None):
                @parse_handler
                def wrapper():
                    if os.path.exists(cache_path):
                        with open(cache_path, "rt") as fd:
                            result = fd.read().strip()
                            if len(result) > 0:
                                return Device(result)
                    raise AdbError("no device used last time")

                setattr(namespace, self.dest, wrapper)

        group = parser.add_argument_group(title="adb optional arguments").add_mutually_exclusive_group()
        group.add_argument("-s", "--serial", metavar="SERIAL", dest="parse_device", action=SerialAction,
                           help="use device with given serial (adb -s option)", default=parse_device)
        group.add_argument("-d", "--device", dest="parse_device", nargs=0, const=True, action=DeviceAction,
                           help="use USB device (adb -d option)")
        group.add_argument("-e", "--emulator", dest="parse_device", nargs=0, const=True, action=EmulatorAction,
                           help="use TCP/IP device (adb -e option)")
        group.add_argument("-c", "--connect", metavar="IP[:PORT]", dest="parse_device", action=ConnectAction,
                           help="use device with TCP/IP")
        group.add_argument("-l", "--last", dest="parse_device", nargs=0, const=True, action=LastAction,
                           help="use last device")


class IOSScript(ConsoleScript, ABC):

    def _get_known_errors(self) -> Tuple[Type[BaseException]]:
        from linktools.ios import SibError
        return SibError,

    def _add_base_arguments(self, parser: ArgumentParser):
        super()._add_base_arguments(parser)

        from linktools.ios import Sib, SibError, Device

        cache_path = environ.resource.get_temp_path("cache", "device", "ios", create_parent=True)

        def parse_handler(fn):
            @functools.wraps(fn)
            def wrapper(*args, **kwargs):
                device = fn(*args, **kwargs)
                if device is not None:
                    with open(cache_path, "wt+") as fd:
                        fd.write(device.id)
                return device

            return wrapper

        @parse_handler
        def parse_device():
            devices = Sib.devices()
            if len(devices) == 0:
                raise SibError("no devices/emulators found")

            if len(devices) == 1:
                return devices[0]

            table = Table(show_lines=True)
            table.add_column("Index", justify="right", style="cyan", no_wrap=True)
            table.add_column("UDID", style="magenta")
            table.add_column("Name", style="magenta")

            offset = 1
            for i in range(len(devices)):
                table.add_row(
                    str(i + offset),
                    ignore_error(lambda: devices[i].id),
                    ignore_error(lambda: devices[i].name),
                )

            console = get_console()
            console.print(table)

            prompt = f"More than one device/emulator. {os.linesep}" \
                     f"Enter device index"
            choices = [str(i) for i in range(offset, len(devices) + offset, 1)]
            index = IntPrompt.ask(prompt, choices=choices, default=offset, console=console)

            return devices[index - offset]

        class UdidAction(Action):

            def __call__(self, parser, namespace, values, option_string=None):
                @parse_handler
                def wrapper():
                    return Device(str(values))

                setattr(namespace, self.dest, wrapper)

        class LastAction(Action):

            def __call__(self, parser, namespace, values, option_string=None):
                @parse_handler
                def wrapper():
                    if os.path.exists(cache_path):
                        with open(cache_path, "rt") as fd:
                            result = fd.read().strip()
                            if len(result) > 0:
                                return Device(result)
                    raise SibError("no device used last time")

                setattr(namespace, self.dest, wrapper)

        group = parser.add_argument_group(title="device optional arguments")
        group = group.add_mutually_exclusive_group()
        group.add_argument("-u", "--udid", metavar="UDID", dest="parse_device", action=UdidAction,
                           help="specify unique device identifier", default=parse_device)
        group.add_argument("-l", "--last", dest="parse_device", nargs=0, const=True, action=LastAction,
                           help="use last device")
