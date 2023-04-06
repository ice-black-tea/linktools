#!/usr/bin/env python3
# -*- coding:utf-8 -*-

from abc import ABC, abstractmethod
from typing import Any, Generator

from . import utils, Tool, ToolExecError


class BridgeError(Exception):
    pass


class Bridge:

    @classmethod
    def list_devices(cls, alive: bool = None) -> Generator["BaseDevice", None, None]:
        from .android import Adb
        from .ios import Sib
        for device in Adb.list_devices(alive=alive):
            yield device
        for device in Sib.list_devices(alive=alive):
            yield device

    @classmethod
    def get_error_class(cls):
        return BridgeError

    @classmethod
    @abstractmethod
    def get_tool(cls) -> Tool:
        pass

    @classmethod
    def popen(cls, *args: [Any], **kwargs) -> utils.Popen:
        return cls.get_tool().popen(*args, **kwargs)

    @classmethod
    def exec(cls, *args: [Any], timeout: utils.TimeoutType = None,
             ignore_errors: bool = False, log_output: bool = False) -> str:
        """
        执行命令
        :param args: 命令
        :param timeout: 超时时间
        :param ignore_errors: 忽略错误，报错不会抛异常
        :param log_output: 把输出打印到logger中
        :return: 如果是不是守护进程，返回输出结果；如果是守护进程，则返回Popen对象
        """
        try:
            return cls.get_tool().exec(
                *args,
                timeout=timeout,
                ignore_errors=ignore_errors,
                log_output=log_output,
            )
        except ToolExecError as e:
            error_class = cls.get_error_class()
            raise error_class(e)


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

