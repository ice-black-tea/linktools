#!/usr/bin/env python3
# -*- coding:utf-8 -*-
from abc import ABC, abstractmethod
from typing import Any, Generator, TypeVar, Callable

from . import utils, Tool, environ
from .decorator import timeoutable
from .types import TimeoutType, Error

BridgeType = TypeVar("BridgeType", bound="Bridge")
DeviceType = TypeVar("DeviceType", bound="BaseDevice")

_logger = environ.get_logger("device")


class BridgeError(Error):
    pass


class Bridge(ABC):

    def __init__(
            self,
            tool: Tool,
            options: [str] = None,
            error_type: Callable[[str], BridgeError] = BridgeError,
            on_stdout: Callable[[str], None] = _logger.info,
            on_stderr: Callable[[str], None] = _logger.error):
        self._tool = tool
        self._options = options or []
        self._error_type = error_type
        self._on_stdout = on_stdout
        self._on_stderr = on_stderr

    @abstractmethod
    def list_devices(self, alive: bool = None) -> Generator["BaseDevice", None, None]:
        """
        获取所有设备列表
        :param alive: 只显示在线的设备
        :return: 设备对象
        """
        pass

    def popen(self, *args: Any, **kwargs) -> utils.Process:
        """
        执行命令
        :param args: 命令参数
        :param kwargs: 其他参数
        :return: 返回进程对象
        """
        return self._tool.popen(
            *(*self._options, *args),
            **kwargs
        )

    @timeoutable
    def exec(self, *args: Any, timeout: TimeoutType = None,
             ignore_errors: bool = False, log_output: bool = False) -> str:
        """
        执行命令
        :param args: 命令参数
        :param timeout: 超时时间
        :param ignore_errors: 忽略错误，报错不会抛异常
        :param log_output: 把输出打印到logger中
        :return: 返回输出结果
        """
        return self._tool.exec(
            *(*self._options, *args),
            timeout=timeout,
            ignore_errors=ignore_errors,
            on_stdout=self._on_stdout if log_output else None,
            on_stderr=self._on_stderr if log_output else None,
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

    @abstractmethod
    def copy(self, timeout: TimeoutType):
        """
        获取设备名
        :param timeout: 超时时间
        :return: 设备名
        """
        pass


def list_devices(alive: bool = None) -> Generator["BaseDevice", None, None]:
    """
    获取所有设备列表（包括Android、iOS、Harmony）
    :param alive: 只显示在线的设备
    :return: 设备对象
    """
    from .android import Adb
    from .ios import Sib
    from .harmony import Hdc
    for device in Adb().list_devices(alive=alive):
        yield device
    for device in Sib().list_devices(alive=alive):
        yield device
    for device in Hdc().list_devices(alive=alive):
        yield device
