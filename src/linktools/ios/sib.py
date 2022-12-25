#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import json
import subprocess
from subprocess import TimeoutExpired
from typing import Any, AnyStr

from .. import utils, tools, ToolExecError
from .._logging import get_logger
from ..decorator import cached_property

_logger = get_logger("android.adb")


class SibError(Exception):
    pass


class Sib(object):
    _ALIVE_STATUS = ("online",)

    @classmethod
    def devices(cls, alive: bool = None) -> ["Device"]:
        """
        获取所有设备列表
        :param alive: 只显示在线的设备
        :return: 设备号数组
        """
        devices = []
        result = cls.exec("devices", "--detail")
        result = utils.ignore_error(json.loads, result) or []
        for info in utils.get_list_item(result, "deviceList", default=[]):
            id = utils.get_item(info, "serialNumber")
            status = utils.get_item(info, "status")
            if alive is None:
                devices.append(Device(id, info))
            elif alive == (status in cls._ALIVE_STATUS):
                devices.append(Device(id, info))

        return devices

    @classmethod
    def popen(cls, *args: [Any], **kwargs) -> utils.Popen:
        return tools["sib"].popen(*args, **kwargs)

    @classmethod
    def exec(cls, *args: [Any], input: AnyStr = None, timeout: float = None,
             ignore_errors: bool = False, output_to_logger: bool = False) -> str:
        """
        执行命令
        :param args: 命令
        :param input: 输入
        :param timeout: 超时时间
        :param ignore_errors: 忽略错误，报错不会抛异常
        :param output_to_logger: 把输出打印到logger中
        :return: 如果是不是守护进程，返回输出结果；如果是守护进程，则返回Popen对象
        """
        try:
            return tools["sib"].exec(
                *args,
                input=input,
                timeout=timeout,
                ignore_errors=ignore_errors,
                output_to_logger=output_to_logger,
            )
        except ToolExecError as e:
            raise SibError(e)


class Device(object):

    def __init__(self, id: str = None, info: dict = None):
        """
        :param id: 设备号
        """
        if id is None:
            devices = Sib.devices(alive=True)
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
        for device in Sib.devices():
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
        args = [*args, "--udid", self.id]
        return Sib.popen(*args, **kwargs)

    def exec(self, *args: [Any], **kwargs) -> str:
        """
        执行命令
        :param args: 命令行参数
        :return: sib输出结果
        """
        args = [*args, "--udid", self.id]
        return Sib.exec(*args, **kwargs)

    def install(self, path: str, **kwargs) -> str:
        return self.exec("app", "install", "--path", path, **kwargs)

    def uninstall(self, bundle_id: str, **kwargs) -> str:
        return self.exec("app", "uninstall", "--bundleId", bundle_id, **kwargs)

    def forward(self, local_port: int, remote_port: int) -> utils.Stoppable:

        process = self.popen(
            "proxy",
            "--local-port", local_port,
            "--remote-port", remote_port,
            stdout=subprocess.DEVNULL,  # None if environ.debug else subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,  # None if environ.debug else subprocess.DEVNULL,
            stdin=subprocess.PIPE,
        )
        process.call_as_daemon(timeout=1)

        class Stoppable(utils.Stoppable):

            def stop(self):
                try:
                    _logger.debug(f"Kill sib proxy process")
                    process.kill()
                    process.wait(5)
                except TimeoutExpired:
                    _logger.error(f"Proxy process did not finish normally")

        return Stoppable()

    def __repr__(self):
        return f"iOSDevice<{self.id}>"
