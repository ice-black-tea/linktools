#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import json
import subprocess
import time
from subprocess import TimeoutExpired
from typing import Any, Generator

from .. import utils
from .._environ import environ
from ..device import BridgeError, Bridge, BaseDevice
from ..decorator import cached_property
from ..reactor import Stoppable

_logger = environ.get_logger("android.adb")


class SibError(BridgeError):
    pass


class Sib(Bridge):
    _ALIVE_STATUS = ("online",)

    @classmethod
    def list_devices(cls, alive: bool = None) -> Generator["Device", None, None]:
        """
        获取所有设备列表
        :param alive: 只显示在线的设备
        :return: 设备号数组
        """
        result = cls.exec("devices", "--detail")
        result = utils.ignore_error(json.loads, result) or []
        for info in utils.get_list_item(result, "deviceList", default=[]):
            id = utils.get_item(info, "serialNumber")
            status = utils.get_item(info, "status")
            if alive is None:
                yield Device(id, info)
            elif alive == (status in cls._ALIVE_STATUS):
                yield Device(id, info)

    @classmethod
    def get_tool(cls):
        return environ.get_tool("sib")

    @classmethod
    def get_error_class(cls):
        return SibError


class Device(BaseDevice):

    def __init__(self, id: str = None, info: dict = None):
        """
        :param id: 设备号
        """
        if id is None:
            devices = list(Sib.list_devices(alive=True))
            if len(devices) == 0:
                raise SibError("no devices/emulators found")
            elif len(devices) > 1:
                raise SibError("more than one device/emulator")
            self._id = devices[0]._id
            self._info = devices[0]._info
        else:
            self._id = id
            self._info = info

    @property
    def id(self) -> str:
        """
        获取设备号
        :return: 设备号
        """
        return self._id

    @property
    def name(self) -> str:
        return self.detail.get("deviceName")

    @property
    def version(self) -> str:
        return self.detail.get("productVersion")

    @property
    def address(self) -> str:
        return self.info.get("remoteAddr")

    @cached_property
    def info(self) -> dict:
        """
        获取设备abi类型
        :return: abi类型
        """
        if self._info is not None:
            return self._info
        for device in Sib.list_devices():
            if device.id == self.id:
                return device.info
        raise SibError(f"device '{self.id}' not found")

    @cached_property
    def detail(self) -> dict:
        return self.info.get("deviceDetail")

    def popen(self, *args: [Any], **kwargs) -> utils.Popen:
        """
        执行命令
        :param args: 命令行参数
        :return: 打开的进程
        """
        args = ["--udid", self.id, *args]
        return Sib.popen(*args, **kwargs)

    def exec(self, *args: [Any], **kwargs) -> str:
        """
        执行命令
        :param args: 命令行参数
        :return: sib输出结果
        """
        args = ["--udid", self.id, *args]
        return Sib.exec(*args, **kwargs)

    def install(self, path: str, **kwargs) -> str:
        return self.exec("app", "install", "--path", path, **kwargs)

    def uninstall(self, bundle_id: str, **kwargs) -> str:
        return self.exec("app", "uninstall", "--bundleId", bundle_id, **kwargs)

    def forward(self, local_port: int, remote_port: int):
        process = self.popen(
            "proxy",
            "--local-port", local_port,
            "--remote-port", remote_port,
            text=True,
            bufsize=1,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        for i in range(10):
            if process.poll() is not None:
                break
            out, err = process.exec(timeout=1, log_stderr=True)
            if out:
                if isinstance(out, bytes):
                    out = out.decode(errors="ignore")
                if "Listen on:" in out:
                    time.sleep(.1)
                    _logger.debug(f"Capture sib proxy process output: {out.rstrip()}")
                    break

        class Forward(Stoppable):

            def stop(self):
                try:
                    _logger.debug(f"Kill sib proxy process")
                    process.kill()
                    process.wait(5)
                except TimeoutExpired:
                    _logger.error(f"Proxy process did not finish normally")

        return Forward()

    def __repr__(self):
        return f"iOSDevice<{self.id}>"
