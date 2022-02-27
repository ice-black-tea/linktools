#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Author    : HuJi <jihu.hj@alibaba-inc.com>
# Datetime  : 2022/2/25 6:30 PM
# User      : huji
# Product   : PyCharm
# Project   : link
import logging
from typing import Union, Optional

import logzero
import tidevice

MuxError = tidevice.MuxError

logzero.loglevel(logging.WARNING)


class Usbmux(tidevice.Usbmux):
    __default_usbmux = None

    @classmethod
    def set_default(cls, usbmux: Union["Usbmux", str]):
        if isinstance(usbmux, str):
            cls.__default_usbmux = Usbmux(usbmux)
        elif isinstance(usbmux, Usbmux):
            cls.__default_usbmux = usbmux

    @classmethod
    def get_default(cls):
        return cls.__default_usbmux


class Device(tidevice.Device):

    def __init__(self, udid: Optional[str] = None, usbmux: Union[Usbmux, str, None] = None):
        super().__init__(udid, usbmux or Usbmux.get_default())

    def relay(self, local_port: int, remote_port: int):
        from tidevice._relay import relay
        relay(self, local_port, remote_port)


Usbmux.set_default(Usbmux())
