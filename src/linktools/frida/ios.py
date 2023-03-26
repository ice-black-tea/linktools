#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Author    : HuJi <jihu.hj@alibaba-inc.com>
# Datetime  : 2022/2/26 11:03 PM
# User      : huji
# Product   : PyCharm
# Project   : link

import frida

from .server import FridaServer
from .. import utils, environ
from ..ios import Device

_logger = environ.get_logger("frida.server.ios")


class IOSFridaServer(FridaServer):  # proxy for frida.core.Device
    """
    ios server
    """

    def __init__(self, device: Device = None, local_port: int = 37042, remote_port: int = 27042):
        super().__init__(frida.get_device_manager().add_remote_device(f"localhost:{local_port}"))
        self._device = device or Device()
        self._local_port = local_port
        self._remote_port = remote_port
        self._forward = None

    @property
    def local_port(self):
        return self._local_port

    @property
    def remote_port(self):
        return self._remote_port

    def _start(self):
        if self._forward is None:
            self._forward = self._device.forward(self._local_port, self._remote_port)

    def _stop(self):
        if self._forward is not None:
            utils.ignore_error(self._forward.stop)
            self._forward = None
