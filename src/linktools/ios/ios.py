#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : ios.py
@time    : 2024/10/14 16:25 
@site    : https://github.com/ice-black-tea
@software: PyCharm

              ,----------------,              ,---------,
         ,-----------------------,          ,"        ,"|
       ,"                      ,"|        ,"        ,"  |
      +-----------------------+  |      ,"        ,"    |
      |  .-----------------.  |  |     +---------+      |
      |  |                 |  |  |     | -==----'|      |
      |  | $ sudo rm -rf / |  |  |     |         |      |
      |  |                 |  |  |/----|`---=    |      |
      |  |                 |  |  |   ,/|==== ooo |      ;
      |  |                 |  |  |  // |(((( [33]|    ,"
      |  `-----------------'  |," .;'| |((((     |  ,"
      +-----------------------+  ;;  | |         |,"
         /_)______________(_/  //'   | +---------+
    ___________________________/___  `,
   /  oooooooooooooooo  .o.  oooo /,   `,"-----------
  / ==ooooooooooooooo==.o.  ooo= //   ,``--{)B     ,"
 /_==__==========__==_ooo__ooo=_/'   /___________,"
"""
import json
import subprocess
import time
from subprocess import TimeoutExpired
from typing import TYPE_CHECKING, TypeVar, List, Generator, Any, Callable, Union, Tuple, Dict

from ..types import Stoppable
from .. import utils
from .._environ import environ
from ..decorator import timeoutable, cached_property
from ..device import BridgeError, Bridge, BaseDevice

if TYPE_CHECKING:
    from ..ssh import SSHClient

    DEVICE_TYPE = TypeVar("DEVICE_TYPE", bound="GoIOSDevice")

_logger = environ.get_logger("ios.go-ios")


def _load_json(line: str, default: Union[Tuple, Dict] = None) -> Any:
    try:
        return json.loads(line)
    except:
        return default


def _is_log_data(data: Any) -> bool:
    return isinstance(data, dict) and "level" in data and "msg" in data


class GoIOSError(BridgeError):
    pass


class GoIOS(Bridge):

    def __init__(self, options: List[str] = None):
        super().__init__(
            tool=environ.get_tool("ios"),
            options=options,
            error_type=self._on_error,
            on_stdout=self._on_log,
            on_stderr=self._on_log,
        )

    @classmethod
    def _on_log(cls, message: str):
        for line in message.splitlines():
            data = _load_json(line)
            if _is_log_data(data):
                level = data.get("level")
                if level in ("error", "fatal"):
                    _logger.error(data.get("msg"))
                elif level == ("warning",):
                    _logger.warning(data.get("msg"))
                elif level in ("trace", "debug"):
                    _logger.debug(data.get("msg"))
                else:
                    _logger.info(data.get("msg"))

    @classmethod
    def _on_error(cls, message: str):
        for line in message.splitlines():
            data = _load_json(line)
            if _is_log_data(data):
                level = data.get("level")
                if level in ("fatal",):
                    return GoIOSError(data.get("msg"))
        return GoIOSError(message)

    def list_devices(self, alive: bool = None) -> Generator["GoIOSDevice", None, None]:
        """
        获取所有设备列表
        :param alive: 只显示在线的设备
        :return: 设备号数组
        """
        result = self.exec("list")
        for line in result.splitlines():
            data = _load_json(line)
            if isinstance(data, dict) and "deviceList" in data:
                for id in data["deviceList"]:
                    if alive is None:
                        yield GoIOSDevice(id, ios=self)
                    elif alive is True:  # online only
                        yield GoIOSDevice(id, ios=self)


class GoIOSDevice(BaseDevice):

    def __init__(self, id: str = None, ios: GoIOS = None):
        """
        :param id: 设备号
        :param ios: IOS对象
        """
        self._ios = ios or GoIOS()
        if id is None:
            devices = list(self._ios.list_devices(alive=True))
            if len(devices) == 0:
                raise GoIOSError("no devices/emulators found")
            elif len(devices) > 1:
                raise GoIOSError("more than one device/emulator")
            self._id = devices[0]._id
        else:
            self._id = id

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
        return self.info.get("DeviceName")

    @property
    def version(self) -> str:
        """
        获取系统版本
        :return: 系统版本
        """
        return self.info.get("ProductVersion")

    @property
    def type(self) -> str:
        """
        获取设备型号
        :return: 设备型号
        """
        return self.info.get("ProductType")

    @cached_property
    def info(self) -> dict:
        """
        获取设备详细信息
        :return: 设备类型
        """
        for line in self.exec("info").splitlines():
            return _load_json(line, {})
        raise GoIOSError("get device info failed")

    def copy(self, type: "Callable[[str, GoIOS], DEVICE_TYPE]" = None) -> "DEVICE_TYPE":
        """
        生成一个新的设备对象
        :param type: 设备类型
        :return: 新的设备对象
        """
        return (type or GoIOSDevice)(self._id, self._ios)

    def popen(self, *args: Any, **kwargs) -> utils.Process:
        """
        执行命令
        :param args: 命令行参数
        :return: 打开的进程
        """
        args = ["--udid", self.id, *args]
        return self._ios.popen(*args, **kwargs)

    @timeoutable
    def exec(self, *args: Any, **kwargs) -> str:
        """
        执行命令
        :param args: 命令行参数
        :return: sib输出结果
        """
        args = ["--udid", self.id, *args]
        return self._ios.exec(*args, **kwargs)

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
        return self.exec("install", f"--path={ipa_path}", **kwargs)

    @timeoutable
    def uninstall(self, bundle_id: str, **kwargs) -> str:
        """
        卸载应用
        :param bundle_id: 包名
        :return: sib输出结果
        """
        return self.exec("uninstall", bundle_id, **kwargs)

    @timeoutable
    def kill(self, bundle_id: str, **kwargs) -> str:
        """
        结束应用
        :param bundle_id: 包名
        :return: sib输出结果
        """
        return self.exec("kill", bundle_id, **kwargs)

    def forward(self, local_port: int, remote_port: int) -> "Forward":
        """
        创建端口转发
        :param local_port: 本地端口
        :param remote_port: 远程端口
        :return: 端口转发对象
        """
        return Forward(self, local_port, remote_port)

    def ssh(self, port: int = 22, username: str = "root", password: str = None) -> "SSHClient":
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
        return f"IOSDevice<{self.id}>"


class Forward(Stoppable):
    local_port = property(lambda self: self._local_port)
    remote_port = property(lambda self: self._remote_port)

    def __init__(self, ios: GoIOSDevice, local_port: int, remote_port: int):
        self._local_port = local_port
        self._remote_port = remote_port
        self._process = ios.popen(
            "forward",
            local_port,
            remote_port,
            text=True,
            bufsize=1,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        for i in range(10):
            out, err = self._process.exec(timeout=1)
            for line in (out or "").splitlines() + (err or "").splitlines():
                data = _load_json(line)
                if _is_log_data(data):
                    level = data.get("level")
                    if level in ("fatal",):
                        utils.ignore_error(self._process.kill)
                        raise GoIOSError(data.get("msg"))
                    elif "Start listening on port" in data["msg"]:
                        time.sleep(.01)
                        _logger.debug(f"Capture ios forward process output: {data['msg']}")
                        return

        raise GoIOSError("Run ios forward failed")

    def stop(self):
        try:
            _logger.debug(f"Kill ios proxy process")
            self._process.kill()
            self._process.wait(5)
        except TimeoutExpired:
            _logger.error(f"Proxy process did not finish normally")


if __name__ == '__main__':
    import logging

    logging.basicConfig(level=logging.DEBUG)
    device = GoIOSDevice()
    # # print(device.info)
    # print(device.name)
    # print(device.version)
    # print(GoIOSDevice("11").info)
    # print(device.exec("ps", log_output=True))
    with device.ssh(22, "root", "alpine") as ssh:
        ssh.open_shell()
