#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Author    : HuJi <jihu.hj@alibaba-inc.com>
# Datetime  : 2022/2/25 6:45 PM
# User      : huji
# Product   : PyCharm
# Project   : link

import fnmatch
import lzma
import os
import shutil
from typing import Optional

import frida

from .server import FridaServer
from .. import environ, utils
from ..android import Device
from ..reactor import Stoppable

_logger = environ.get_logger("frida.server.android")


class AndroidFridaServer(FridaServer):
    """
    android server
    """

    def __init__(self, device: Device = None, local_port: int = 47042, remote_port: int = 47042):
        super().__init__(frida.get_device_manager().add_remote_device(f"localhost:{local_port}"))
        self._device = device or Device()
        self._local_port = local_port
        self._remote_port = remote_port
        self._forward: Optional[Stoppable] = None
        self._executable = self.Executable(self._device.abi, frida.__version__)

        self._server_prefix = "fs-ln-"
        self._server_name = f"{self._server_prefix}{utils.make_uuid()}"
        self._server_dir = self._device.get_data_path("fs-ln")
        self._server_path = self._device.get_data_path("fs-ln", self._server_name)

    @property
    def local_port(self):
        return self._local_port

    @property
    def remote_port(self):
        return self._remote_port

    @classmethod
    def setup(cls, abis: [str] = ("arm", "arm64", "x86_64", "x86"), version: str = frida.__version__):
        for abi in abis:
            exe = cls.Executable(abi, version)
            exe.prepare()

    def _start(self):

        remote_name = f"fs-{self._device.abi}-{frida.__version__}"
        remote_path = self._device.get_data_path(remote_name)

        # 先下载frida server，然后把server推送到设备上
        if not self._device.is_file_exist(remote_path):
            _logger.info(f"Push frida server to remote: {remote_path}")
            temp_path = self._device.get_storage_path("frida", remote_name)
            self._executable.prepare()
            self._device.push(self._executable.path, temp_path, log_output=True)
            self._device.sudo("mv", temp_path, remote_path, log_output=True)
            self._device.sudo("chmod", "755", remote_path, log_output=True)

        # 转发端口
        self._forward = self._device.forward(f"tcp:{self._local_port}", f"tcp:{self._remote_port}")

        try:
            # 创建软链
            self._device.sudo("mkdir", "-p", self._server_dir)
            self._device.sudo("ln", "-s", remote_path, self._server_path)

            # 接下来新开一个进程运行frida server，并且输出一下是否出错
            self._device.sudo(
                self._server_path,
                "-d", "fs-binaries",
                "-l", f"0.0.0.0:{self._remote_port}",
                "-D", "&",
                ignore_errors=True,
                log_output=True,
            )
        finally:
            # 删除软连接
            self._device.sudo("rm", self._server_path, ignore_errors=True)

    def _stop(self):
        try:
            # 就算杀死adb进程，frida server也不一定真的结束了，所以kill一下frida server进程
            process_name_lc = f"{self._server_prefix}*".lower()
            for process in self._device.get_processes():
                if fnmatch.fnmatchcase(process.name.lower(), process_name_lc):
                    _logger.debug(f"Find frida server process({process.name}:{process.pid}), kill it")
                    self._device.sudo("kill", "-9", process.pid, ignore_errors=True)
        finally:
            # 把转发端口给移除了，不然会一直占用这个端口
            self._forward.stop()

    class Executable:

        def __init__(self, abi: str, version: str):
            cfg = environ.get_config("ANDROID_TOOL_FRIDA_SERVER", type=dict)
            cfg.update(version=version, abi=abi)

            self.url = cfg["url"].format(**cfg)
            self.name = cfg["name"].format(**cfg)
            self.path = environ.get_data_path("frida", self.name, create_parent=True)

        def prepare(self):
            if os.path.exists(self.path):
                return
            _logger.info("Download frida server ...")
            with utils.UrlFile(self.url) as file:
                if os.path.exists(self.path):
                    return
                with lzma.open(file.save(), "rb") as read, open(self.path, "wb") as write:
                    shutil.copyfileobj(read, write)
                file.clear()
