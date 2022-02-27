#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Author    : HuJi <jihu.hj@alibaba-inc.com>
# Datetime  : 2022/2/26 11:03 PM
# User      : huji
# Product   : PyCharm
# Project   : link
import billiard
import frida

from linktools import logger, utils
from linktools.frida import FridaServer
from linktools.ios import Device


class FridaIOSServer(FridaServer):  # proxy for frida.core.Device
    """
    ios server
    """

    def __init__(self, device: Device = None, local_port: int = 37042, remote_port: int = 27042):
        super().__init__(frida.get_device_manager().add_remote_device(f"localhost:{local_port}"))
        self._device = device or Device()
        self._local_port = local_port
        self._remote_port = remote_port
        self._process = None

    @classmethod
    def _run_in_background(cls, device: Device, local_port: int, remote_port: int):
        try:
            device.relay(local_port, remote_port)
        except (KeyboardInterrupt, EOFError):
            pass
        except Exception as e:
            logger.error(e, tag="[!]")

    def _start(self):
        self._process = billiard.context.Process(
            target=self._run_in_background,
            args=(
                self._device,
                self._local_port,
                self._remote_port,
            ),
            daemon=True
        )
        self._process.start()

    def _stop(self):
        if self._process is not None:
            utils.ignore_error(self._process.terminate)
            utils.ignore_error(self._process.join, 5)
            self._process = None
