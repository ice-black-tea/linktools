#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import abc
import functools
import os
from argparse import ArgumentParser, Action
from typing import Type, List

from rich import get_console
from rich.prompt import IntPrompt
from rich.table import Table

from .command import BaseCommand
from ..utils import ignore_error


class IOSCommandMixin:

    def add_ios_arguments(self: BaseCommand, parser: ArgumentParser):

        from ..ios import Sib, SibError, Device as SibDevice

        parser = parser or self._argument_parser
        cache_path = self.environ.get_temp_path("cache", "device", "ios", create_parent=True)

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
            devices = tuple(Sib.list_devices(alive=True))
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
                @parse_handler
                def wrapper():
                    return SibDevice(str(values))

                setattr(namespace, self.dest, wrapper)

        class LastAction(Action):

            def __call__(self, parser, namespace, values, option_string=None):
                @parse_handler
                def wrapper():
                    if os.path.exists(cache_path):
                        with open(cache_path, "rt") as fd:
                            device_id = fd.read().strip()
                        if len(device_id) > 0:
                            return SibDevice(device_id)
                    raise SibError("no device used last time")

                setattr(namespace, self.dest, wrapper)

        class ConnectAction(Action):

            def __call__(self, parser, namespace, values, option_string=None):
                @parse_handler
                def wrapper():
                    address = str(values)
                    host, port = address.split(":", maxsplit=1)
                    Sib.exec("remote", "connect", "--host", host, "--port", port, log_output=True)
                    for device in Sib.list_devices():
                        if address == device.address:
                            return device

                setattr(namespace, self.dest, wrapper)

        group = parser.add_argument_group(title="sib arguments").add_mutually_exclusive_group()
        group.add_argument("-u", "--udid", metavar="UDID", dest="parse_device", action=UdidAction,
                           help="specify unique device identifier", default=parse_device)
        group.add_argument("-c", "--connect", metavar="IP:PORT", dest="parse_device", action=ConnectAction,
                           help="use device with TCP/IP")
        group.add_argument("-l", "--last", dest="parse_device", nargs=0, const=True, action=LastAction,
                           help="use last device")


class IOSCommand(BaseCommand, metaclass=abc.ABCMeta):

    @property
    def known_errors(self) -> List[Type[BaseException]]:
        from ..ios import SibError

        return super().known_errors + [SibError]

    def init_base_arguments(self, parser: ArgumentParser):
        super().init_base_arguments(parser)
        IOSCommandMixin.add_ios_arguments(self, parser)
