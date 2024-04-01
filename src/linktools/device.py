#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from abc import ABC, abstractmethod
from typing import Any, Generator, TypeVar, Type

from . import utils, Tool

BridgeType = TypeVar("BridgeType", bound="Bridge")
DeviceType = TypeVar("DeviceType", bound="BaseDevice")


class BridgeError(Exception):
    pass


class Bridge:

    def __init__(self, tool: Tool = None, options: [str] = None, error_type: Type[BridgeError] = BridgeError):
        self._tool = tool
        self._options = options or []
        self._error_type = error_type

    def list_devices(self, alive: bool = None) -> Generator["BaseDevice", None, None]:
        from .android import Adb
        from .ios import Sib
        for device in Adb().list_devices(alive=alive):
            yield device
        for device in Sib().list_devices(alive=alive):
            yield device

    def popen(self, *args: [Any], **kwargs) -> utils.Process:
        if self._tool is None:
            raise self._error_type("tool not found")
        return self._tool.popen(
            *(*self._options, *args),
            **kwargs
        )

    @utils.timeoutable
    def exec(self, *args: [Any], timeout: utils.Timeout = None,
             ignore_errors: bool = False, log_output: bool = False) -> str:
        """
        执行命令
        :param args: 命令
        :param timeout: 超时时间
        :param ignore_errors: 忽略错误，报错不会抛异常
        :param log_output: 把输出打印到logger中
        :return: 如果是不是守护进程，返回输出结果；如果是守护进程，则返回Popen对象
        """
        if self._tool is None:
            raise self._error_type("tool not found")
        return self._tool.exec(
            *(*self._options, *args),
            timeout=timeout,
            ignore_errors=ignore_errors,
            log_output=log_output,
            error_type=self._error_type
        )


class BaseDevice(ABC):

    @property
    @abstractmethod
    def id(self) -> str:
        """
        获取设备号
        :return: 设备号
        """
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """
        获取设备号
        :return: 设备名
        """
        pass
