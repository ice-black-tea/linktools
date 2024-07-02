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
from ..decorator import cached_property
from ..device import BridgeError, Bridge, BaseDevice
from ..reactor import Stoppable

if TYPE_CHECKING:
    DEVICE_TYPE = TypeVar("DEVICE_TYPE", bound="Device")

_logger = environ.get_logger("android.adb")


class SibError(BridgeError):
    pass


class Sib(Bridge):

    def __init__(self, options: List[str] = None):
        super().__init__(
            tool=environ.get_tool("sib"),
            options=options,
            error_type=SibError
        )

    def list_devices(self, alive: bool = None) -> Generator["Device", None, None]:
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
                yield Device(id, info)
            elif alive == (status in ("online",)):
                yield Device(id, info)


class Device(BaseDevice):

    def __init__(self, id: str = None, info: Dict = None, sib: Sib = None):
        """
        :param id: 设备号
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
        for device in self._sib.list_devices():
            if device.id == self.id:
                return device.info
        raise SibError(f"device '{self.id}' not found")

    @cached_property
    def detail(self) -> dict:
        return self.info.get("deviceDetail")

    def copy(self, type: "Callable[[str, Dict, Sib], DEVICE_TYPE]" = None) -> "DEVICE_TYPE":
        return (type or Device)(self._id, self._info, self._sib)

    def popen(self, *args: [Any], **kwargs) -> utils.Process:
        """
        执行命令
        :param args: 命令行参数
        :return: 打开的进程
        """
        args = ["--udid", self.id, *args]
        return self._sib.popen(*args, **kwargs)

    @utils.timeoutable
    def exec(self, *args: [Any], **kwargs) -> str:
        """
        执行命令
        :param args: 命令行参数
        :return: sib输出结果
        """
        args = ["--udid", self.id, *args]
        return self._sib.exec(*args, **kwargs)

    @utils.timeoutable
    def install(self, path_or_url: str, **kwargs) -> str:
        ipa_path = path_or_url
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            environ.logger.info(f"Download file: {path_or_url}")
            file = environ.get_url_file(path_or_url)
            ipa_path = file.download()
            environ.logger.info(f"Save file to local: {ipa_path}")
        return self.exec("app", "install", "--path", ipa_path, **kwargs)

    @utils.timeoutable
    def uninstall(self, bundle_id: str, **kwargs) -> str:
        return self.exec("app", "uninstall", "--bundleId", bundle_id, **kwargs)

    @utils.timeoutable
    def kill(self, bundle_id: str, **kwargs) -> str:
        return self.exec("app", "kill", "--bundleId", bundle_id, **kwargs)

    @utils.timeoutable
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

    @utils.timeoutable
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

    @utils.timeoutable
    def get_processes(self, **kwargs):
        result = []
        objs = json.loads(self.exec("ps", "-f", **kwargs))
        for obj in objs:
            result.append(Process(obj))
        return result

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

    def reverse(self, remote_port: int, local_port: int, *,
                ssh_port: int = 22, ssh_username: str = "root"):

        import paramiko
        from linktools.ssh import SSHClient

        forward = self.forward(
            local_port=utils.pick_unused_port(range(20000, 30000)),
            remote_port=ssh_port,
        )

        ssh_client = SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect_with_pwd(
            "localhost",
            port=forward.local_port,
            username=ssh_username,
        )
        reverse = ssh_client.reverse(
            forward_host="localhost",
            forward_port=local_port,
            remote_port=remote_port
        )

        class Reverse(Stoppable):
            local_port = property(lambda self: local_port)
            remote_port = property(lambda self: reverse.remote_port)

            def stop(self):
                reverse.stop()
                forward.stop()

        return Reverse()

    def __repr__(self):
        return f"SibDevice<{self.id}>"
