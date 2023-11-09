#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import abc
import functools
import os
from argparse import ArgumentParser, Action, Namespace
from typing import Optional, Callable, List, Type

from rich import get_console
from rich.prompt import IntPrompt
from rich.table import Table

from .command import BaseCommand
from ..android import Adb, AdbError, Device as AdbDevice
from ..device import Bridge, BridgeError, BaseDevice, BridgeType, DeviceType
from ..ios import Sib, SibError, Device as SibDevice
from ..utils import ignore_error


class DeviceCache:

    def __init__(self, path: str):
        self.path = path

    def read(self) -> Optional[str]:
        if os.path.exists(self.path):
            with open(self.path, "rt") as fd:
                return fd.read().strip()
        return None

    def write(self, cache: str) -> None:
        with open(self.path, "wt") as fd:
            fd.write(cache)

    def __call__(self, fn: Callable[..., BaseDevice]):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            device: BaseDevice = fn(*args, **kwargs)
            if device is not None:
                self.write(device.id)
            return device

        return wrapper


class DeviceParser:

    def __init__(self, func: Callable[[BridgeType], DeviceType] = None, options: List[str] = None):
        self.func = func
        self.options = options or []
        self._default = True

    @property
    def bridge(self) -> BridgeType:
        return Bridge(*self.options)

    def __call__(self):
        return self.func(self.bridge)

    @classmethod
    def copy_on_write(cls, namespace: Namespace, dest: str) -> "DeviceParser":
        if hasattr(namespace, dest):
            parser: DeviceParser = getattr(namespace, dest)
            if not parser:
                parser = cls()
                parser._default = False
                setattr(namespace, dest, parser)
            elif parser._default:
                new_parser = cls()
                new_parser.func = parser.func
                new_parser.options = list(parser.options)
                new_parser._default = False
                setattr(namespace, dest, new_parser)
                return new_parser
        else:
            parser = cls()
            parser._default = False
            setattr(namespace, dest, parser)
        return parser


class AndroidParser(DeviceParser):

    @property
    def bridge(self):
        return Adb(*self.options)


class IOSParser(DeviceParser):

    @property
    def bridge(self):
        return Sib(*self.options)


class DeviceCommandMixin:

    def add_device_options(self: "BaseCommand", parser: ArgumentParser):

        parser = parser or self.argument_parser
        cache = DeviceCache(
            self.environ.get_temp_path(
                "cache", "device", "mobile",
                create_parent=True
            )
        )

        @cache
        def parse_device(bridge: Bridge):
            devices = tuple(bridge.list_devices(alive=True))
            if len(devices) == 0:
                raise BridgeError("no devices/emulators found")

            if len(devices) == 1:
                return devices[0]

            table = Table(show_lines=True)
            table.add_column("Index", justify="right", style="cyan", no_wrap=True)
            table.add_column("ID", style="magenta")
            table.add_column("Name", style="magenta")

            offset = 1
            for i in range(len(devices)):
                table.add_row(
                    str(i + offset),
                    ignore_error(lambda: devices[i].id),
                    ignore_error(lambda: devices[i].name) or "",
                )

            console = get_console()
            console.print(table)

            prompt = f"More than one device/emulator. {os.linesep}" \
                     f"Enter device index"
            choices = [str(i) for i in range(offset, len(devices) + offset, 1)]
            index = IntPrompt.ask(prompt, choices=choices, default=offset, console=console)

            return devices[index - offset]

        class IDAction(Action):

            def __call__(self, parser, namespace, values, option_string=None):
                @cache
                def wrapper(bridge: Bridge):
                    device_id = str(values)
                    for device in bridge.list_devices():
                        if device.id == device_id:
                            return device
                    raise BridgeError(f"no devices/emulators with {device_id} found")

                device_parser = DeviceParser.copy_on_write(namespace, self.dest)
                device_parser.func = wrapper

        class LastAction(Action):

            def __call__(self, parser, namespace, values, option_string=None):
                @cache
                def wrapper(bridge: Bridge):
                    device_id = cache.read()
                    if device_id:
                        raise BridgeError("no device used last time")
                    for device in bridge.list_devices():
                        if device.id == device_id:
                            return device
                    raise BridgeError("no device used last time")

                device_parser = DeviceParser.copy_on_write(namespace, self.dest)
                device_parser.func = wrapper

        group = parser.add_argument_group(title="mobile device options").add_mutually_exclusive_group()
        group.add_argument("-i", "--id", metavar="ID", dest="parse_device", action=IDAction,
                           help="specify unique device identifier", default=DeviceParser(parse_device))
        group.add_argument("-l", "--last", dest="parse_device", nargs=0, const=True, action=LastAction,
                           help="use last device")


class AndroidCommandMixin:

    def add_android_options(self: BaseCommand, parser: ArgumentParser) -> None:

        parser = parser or self.argument_parser
        cache = DeviceCache(
            self.environ.get_temp_path(
                "cache", "device", "android",
                create_parent=True
            )
        )

        @cache
        def parse_device(adb: Adb):
            devices = tuple(adb.list_devices(alive=True))
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
                    ignore_error(lambda: devices[i].id),
                    ignore_error(lambda: devices[i].name) or "",
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
                @cache
                def wrapper(adb: Adb):
                    return AdbDevice(str(values), adb=adb)

                device_parser = AndroidParser.copy_on_write(namespace, self.dest)
                device_parser.func = wrapper

        class DeviceAction(Action):

            def __call__(self, parser, namespace, values, option_string=None):
                @cache
                def wrapper(adb: Adb):
                    return AdbDevice(adb.exec("-d", "get-serialno").strip(" \r\n"), adb=adb)

                device_parser = AndroidParser.copy_on_write(namespace, self.dest)
                device_parser.func = wrapper

        class EmulatorAction(Action):

            def __call__(self, parser, namespace, values, option_string=None):
                @cache
                def wrapper(adb: Adb):
                    return AdbDevice(adb.exec("-e", "get-serialno").strip(" \r\n"), adb=adb)

                device_parser = AndroidParser.copy_on_write(namespace, self.dest)
                device_parser.func = wrapper

        class ConnectAction(Action):

            def __call__(self, parser, namespace, values, option_string=None):
                @cache
                def wrapper(adb: Adb):
                    addr = str(values)
                    if addr.find(":") < 0:
                        addr = addr + ":5555"
                    if addr not in [device.id for device in adb.list_devices()]:
                        adb.exec("connect", addr, log_output=True)
                    return AdbDevice(addr, adb=adb)

                device_parser = AndroidParser.copy_on_write(namespace, self.dest)
                device_parser.func = wrapper

        class LastAction(Action):

            def __call__(self, parser, namespace, values, option_string=None):
                @cache
                def wrapper(adb: Adb):
                    device_id = cache.read()
                    if device_id:
                        return AdbDevice(device_id, adb=adb)
                    raise AdbError("no device used last time")

                device_parser = AndroidParser.copy_on_write(namespace, self.dest)
                device_parser.func = wrapper

        class OptionAction(Action):

            def __call__(self, parser, namespace, values, option_string=None):
                device_parser = AndroidParser.copy_on_write(namespace, self.dest)
                device_parser.options.append(option_string)
                if isinstance(values, str):
                    device_parser.options.append(values)
                elif isinstance(values, (list, tuple, set)):
                    device_parser.options.extend(values)
                else:
                    device_parser.options.append(str(values))

        options = parser.add_argument_group(title="adb options")

        options.add_argument("-a", dest="parse_device", nargs=0, action=OptionAction,
                             default=AndroidParser(parse_device),
                             help="listen on all network interfaces, not just localhost (adb -a option)")

        group = options.add_mutually_exclusive_group()
        group.add_argument("-d", "--device", dest="parse_device", nargs=0, action=DeviceAction,
                           help="use USB device (adb -d option)")
        group.add_argument("-s", "--serial", metavar="SERIAL", dest="parse_device", action=SerialAction,
                           help="use device with given serial (adb -s option)")
        group.add_argument("-e", "--emulator", dest="parse_device", nargs=0, action=EmulatorAction,
                           help="use TCP/IP device (adb -e option)")
        group.add_argument("-c", "--connect", metavar="IP[:PORT]", dest="parse_device", action=ConnectAction,
                           help="use device with TCP/IP")
        group.add_argument("-l", "--last", dest="parse_device", nargs=0, action=LastAction,
                           help="use last device")

        options.add_argument("-t", metavar="ID", dest="parse_device", action=OptionAction,
                             help="use device with given transport ID (adb -t option)")

        group = options.add_mutually_exclusive_group()
        _group = group.add_argument_group()
        _group.add_argument("-H", metavar="HOST", dest="parse_device", action=OptionAction,
                            help="name of adb server host [default=localhost] (adb -H option)")
        _group.add_argument("-P", metavar="PORT", dest="parse_device", action=OptionAction,
                            help="smart socket PORT of adb server [default=5037] (adb -P option)")
        group.add_argument("-L", metavar="SOCKET", dest="parse_device", action=OptionAction,
                           help="listen on given socket for adb server [default=tcp:localhost:5037] (adb -L option)")


class IOSCommandMixin:

    def add_ios_options(self: BaseCommand, parser: ArgumentParser):

        parser = parser or self.argument_parser
        cache = DeviceCache(
            self.environ.get_temp_path(
                "cache", "device", "ios",
                create_parent=True
            )
        )

        @cache
        def parse_device(sib: Sib):
            devices = tuple(sib.list_devices(alive=True))
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
                    ignore_error(lambda: devices[i].name) or "",
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
                @cache
                def wrapper(sib: Sib):
                    return SibDevice(str(values), sib=sib)

                device_parser = IOSParser.copy_on_write(namespace, self.dest)
                device_parser.func = wrapper

        class LastAction(Action):

            def __call__(self, parser, namespace, values, option_string=None):
                @cache
                def wrapper(sib: Sib):
                    device_id = cache.read()
                    if device_id:
                        return SibDevice(device_id, sib=sib)
                    raise SibError("no device used last time")

                device_parser = IOSParser.copy_on_write(namespace, self.dest)
                device_parser.func = wrapper

        class ConnectAction(Action):

            def __call__(self, parser, namespace, values, option_string=None):
                @cache
                def wrapper(sib: Sib):
                    address = str(values)
                    host, port = address.split(":", maxsplit=1)
                    sib.exec("remote", "connect", "--host", host, "--port", port, log_output=True)
                    for device in sib.list_devices():
                        if address == device.address:
                            return device

                device_parser = IOSParser.copy_on_write(namespace, self.dest)
                device_parser.func = wrapper

        group = parser.add_argument_group(title="sib options").add_mutually_exclusive_group()
        group.add_argument("-u", "--udid", metavar="UDID", dest="parse_device", action=UdidAction,
                           help="specify unique device identifier", default=parse_device)
        group.add_argument("-c", "--connect", metavar="IP:PORT", dest="parse_device", action=ConnectAction,
                           help="use device with TCP/IP")
        group.add_argument("-l", "--last", dest="parse_device", nargs=0, const=True, action=LastAction,
                           help="use last device")


class AndroidCommand(BaseCommand, metaclass=abc.ABCMeta):

    @property
    def known_errors(self) -> List[Type[BaseException]]:
        return super().known_errors + [AdbError]

    def init_base_arguments(self, parser: ArgumentParser):
        super().init_base_arguments(parser)
        AndroidCommandMixin.add_android_options(self, parser)


class IOSCommand(BaseCommand, metaclass=abc.ABCMeta):

    @property
    def known_errors(self) -> List[Type[BaseException]]:
        return super().known_errors + [SibError]

    def init_base_arguments(self, parser: ArgumentParser):
        super().init_base_arguments(parser)
        IOSCommandMixin.add_ios_options(self, parser)
