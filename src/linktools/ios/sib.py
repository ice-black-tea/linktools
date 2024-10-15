#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import json
import subprocess
import time
from subprocess import TimeoutExpired
from typing import Any, Generator, List, Callable, Dict, TYPE_CHECKING, TypeVar

from .struct import Process, App
from .. import utils
from .._environ import environ
from ..decorator import cached_property, timeoutable
from ..device import BridgeError, Bridge, BaseDevice
from ..types import Stoppable

if TYPE_CHECKING:
    DEVICE_TYPE = TypeVar("DEVICE_TYPE", bound="SibDevice")

_logger = environ.get_logger("ios.sib")


class SibError(BridgeError):
    pass


class Sib(Bridge):

    def __init__(self, options: List[str] = None):
        super().__init__(
            tool=environ.get_tool("sib"),
            options=options,
            error_type=SibError
        )

    def list_devices(self, alive: bool = None) -> Generator["SibDevice", None, None]:
        """
        获取所有设备列表
        :param alive: 只显示在线的设备
        :return: 设备号数组
        """
        result = self.exec("devices", "--detail")
        result = utils.ignore_error(json.loads, args=(result,)) or []
        for info in utils.get_list_item(result, "deviceList", default=[]):
            id = utils.get_item(info, "serialNumber")
            status = utils.get_item(info, "status")
            if alive is None:
                yield SibDevice(id, info, sib=self)
            elif alive == (status in ("online",)):
                yield SibDevice(id, info, sib=self)


class SibDevice(BaseDevice):

    def __init__(self, id: str = None, info: Dict = None, sib: Sib = None):
        """
        :param id: 设备号
        :param info: 设备信息
        :param sib: sib对象
        """
        self._sib = sib or Sib()
        if id is None:
            devices = list(self._sib.list_devices(alive=True))
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
        """
        获取设备名称
        :return: 设备名称
        """
        return self.detail.get("deviceName")

    @property
    def version(self) -> str:
        """
        获取系统版本
        :return: 系统版本
        """
        return self.detail.get("productVersion")

    @property
    def address(self) -> str:
        """
        获取设备地址
        :return: 设备地址
        """
        return self.info.get("remoteAddr")

    @cached_property
    def info(self) -> dict:
        """
        获取设备详细信息
        :return: 设备信息
        """
        if self._info is not None:
            return self._info
        for device in self._sib.list_devices():
            if device.id == self.id:
                return device.info
        raise SibError(f"device '{self.id}' not found")

    @cached_property
    def detail(self) -> dict:
        """
        获取设备详细信息
        :return: 设备详细信息
        """
        return self.info.get("deviceDetail")

    def copy(self, type: "Callable[[str, Dict, Sib], DEVICE_TYPE]" = None) -> "DEVICE_TYPE":
        """
        生成一个新的设备对象
        :param type: 设备类型
        :return: 新的设备对象
        """
        return (type or SibDevice)(self._id, self._info, self._sib)

    def popen(self, *args: Any, **kwargs) -> utils.Process:
        """
        执行命令
        :param args: 命令行参数
        :return: 打开的进程
        """
        args = ["--udid", self.id, *args]
        return self._sib.popen(*args, **kwargs)

    @timeoutable
    def exec(self, *args: Any, **kwargs) -> str:
        """
        执行命令
        :param args: 命令行参数
        :return: sib输出结果
        """
        args = ["--udid", self.id, *args]
        return self._sib.exec(*args, **kwargs)

    @timeoutable
    def install(self, path_or_url: str, **kwargs) -> str:
        """
        安装应用
        :param path_or_url: 本地路径或者url
        :return: sib输出结果
        """
        _logger.info(f"Install ipa url: {path_or_url}")
        ipa_path = environ.get_url_file(path_or_url).save()
        _logger.debug(f"Local ipa path: {ipa_path}")
        return self.exec("app", "install", "--path", ipa_path, **kwargs)

    @timeoutable
    def uninstall(self, bundle_id: str, **kwargs) -> str:
        """
        卸载应用
        :param bundle_id: 包名
        :return: sib输出结果
        """
        return self.exec("app", "uninstall", "--bundleId", bundle_id, **kwargs)

    @timeoutable
    def kill(self, bundle_id: str, **kwargs) -> str:
        """
        结束应用
        :param bundle_id: 包名
        :return: sib输出结果
        """
        return self.exec("app", "kill", "--bundleId", bundle_id, **kwargs)

    @timeoutable
    def get_app(self, bundle_id: str, detail: bool = None, **kwargs) -> App:
        """
        根据包名获取包信息
        :param bundle_id: 包名
        :param detail: 获取详细信息
        :return: 包信息
        """
        options = ["--format", "--system"]
        if detail is True:
            options.append("--icon")

        out = json.loads(self.exec("app", "list", *options, **kwargs))
        for obj in utils.get_list_item(out, "appList"):
            app = App(obj)
            if bundle_id == app.bundle_id:
                return app

        raise SibError(f"App '{bundle_id}' not found")

    @timeoutable
    def get_apps(self, *bundle_ids: str, system: bool = None, detail: bool = False, **kwargs) -> [App]:
        """
        获取包信息
        :param bundle_ids: 需要匹配的所有包名，为空则匹配所有
        :param system: true只匹配系统应用，false只匹配非系统应用，为空则全匹配
        :param detail: 获取详细信息
        :return: 包信息
        """
        options = ["--format"]
        if detail is True:
            options.append("--icon")
        if system is not False:
            options.append("--system")

        exclude = []
        if system is True:
            exclude = [o.bundle_id for o in self.get_apps(system=False, detail=False, **kwargs)]

        result = []
        out = json.loads(self.exec("app", "list", *options, **kwargs))
        for obj in utils.get_list_item(out, "appList"):
            app = App(obj)
            if app.bundle_id in bundle_ids:
                result.append(app)
            elif app.bundle_id not in exclude:
                result.append(app)

        return result

    @timeoutable
    def get_processes(self, **kwargs):
        """
        获取进程列表
        :return: 进程列表
        """
        result = []
        objs = json.loads(self.exec("ps", "-f", **kwargs))
        for obj in objs:
            result.append(Process(obj))
        return result

    def forward(self, local_port: int, remote_port: int):
        """
        创建端口转发
        :param local_port: 本地端口
        :param remote_port: 远程端口
        :return: 端口转发对象
        """
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
            out, err = process.exec(timeout=1, on_stderr=_logger.error)
            if out:
                if isinstance(out, bytes):
                    out = out.decode(errors="ignore")
                if "Listen on:" in out:
                    time.sleep(.1)
                    _logger.debug(f"Capture sib proxy process output: {out.rstrip()}")
                    break

        class Forward(Stoppable):
            local_port = property(lambda self: local_port)
            remote_port = property(lambda self: remote_port)

            def stop(self):
                try:
                    _logger.debug(f"Kill sib proxy process")
                    process.kill()
                    process.wait(5)
                except TimeoutExpired:
                    _logger.error(f"Proxy process did not finish normally")

        return Forward()

    def ssh(self, port: int = 22, username: str = "root", password: str = None):
        """
        创建ssh连接，需要ios设备已完成越狱
        :param port: ssh端口
        :param username: 用户名
        :param password: 密码
        :return: ssh连接
        """
        import paramiko
        from linktools.ssh import SSHClient

        forward = self.forward(
            local_port=utils.pick_unused_port(range(20000, 30000)),
            remote_port=port,
        )

        class Client(SSHClient):

            def close(self):
                super().close()
                forward.stop()

        ssh_client = Client()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect_with_pwd(
            "localhost",
            port=forward.local_port,
            username=username,
            password=password,
        )

        return ssh_client

    def __repr__(self):
        return f"SibDevice<{self.id}>"
