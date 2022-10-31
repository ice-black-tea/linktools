#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Author    : HuJi <jihu.hj@alibaba-inc.com>
# Datetime  : 2022/2/26 11:03 PM
# User      : huji
# Product   : PyCharm
# Project   : link

import frida

from linktools import get_logger, utils
from linktools.frida import FridaServer
from linktools.ios import Device

logger = get_logger("ios.frida")


class FridaIOSServer(FridaServer):  # proxy for frida.core.Device
    """
    ios server
    """

    def __init__(self, device: Device = None, local_port: int = 37042, remote_port: int = 27042):
        super().__init__(frida.get_device_manager().add_remote_device(f"localhost:{local_port}"))
        self._device = device or Device()
        self._local_port = local_port
        self._remote_port = remote_port
        self._thread = None

    def _start(self):
        self._thread = self._device.forward(self._local_port, self._remote_port)

    def _stop(self):
        if self._thread is not None:
            utils.ignore_error(self._thread.stop)
            utils.ignore_error(self._thread.join, 5)
            self._thread = None
