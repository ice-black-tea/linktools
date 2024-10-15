#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from abc import ABC, abstractmethod
from typing import Any, Generator, TypeVar, Callable

from . import utils, Tool
from .decorator import timeoutable
from .types import TimeoutType, Error

BridgeType = TypeVar("BridgeType", bound="Bridge")
DeviceType = TypeVar("DeviceType", bound="BaseDevice")


class BridgeError(Error):
    pass


class Bridge:

    def __init__(
            self,
            tool: Tool, options: [str] = None,
            error_type: Callable[[str], BridgeError] = BridgeError,
            on_stdout: Callable[[str], None] = None,
            on_stderr: Callable[[str], None] = None):
        self._tool = tool
        self._options = options or []
        self._error_type = error_type
        self._on_stdout = on_stdout
        self._on_stderr = on_stderr

    def list_devices(self, alive: bool = None) -> Generator["BaseDevice", None, None]:
        from .android import Adb
        from .ios import Sib
        from .harmony import Hdc
        for device in Adb().list_devices(alive=alive):
            yield device
        for device in Sib().list_devices(alive=alive):
            yield device
        for device in Hdc().list_devices(alive=alive):
            yield device

    def popen(self, *args: [Any], **kwargs) -> utils.Process:
        return self._tool.popen(
            *(*self._options, *args),
            **kwargs
        )

    @timeoutable
    def exec(self, *args: [Any], timeout: TimeoutType = None,
             ignore_errors: bool = False, log_output: bool = False) -> str:
        """
        执行命令
        :param args: 命令
        :param timeout: 超时时间
        :param ignore_errors: 忽略错误，报错不会抛异常
        :param log_output: 把输出打印到logger中
        :return: 返回输出结果
        """
        return self._tool.exec(
            *(*self._options, *args),
            timeout=timeout,
            ignore_errors=ignore_errors,
            log_output=log_output,
            on_stdout=self._on_stdout,
            on_stderr=self._on_stderr,
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
