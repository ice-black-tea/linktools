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
from .. import resource, config, utils, get_logger
from ..android import adb

_logger = get_logger("frida.server.android")


class AndroidFridaServer(FridaServer):
    """
    android server
    """

    def __init__(self, device: adb.Device = None, local_port: int = 47042, remote_port: int = 47042):
        super().__init__(frida.get_device_manager().add_remote_device(f"localhost:{local_port}"))
        self._device = device or adb.Device()
        self._local_port = local_port
        self._remote_port = remote_port
        self._forward: Optional[utils.Stoppable] = None
        self._environ = self.Environ(self._device.abi, frida.__version__)

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
            env = cls.Environ(abi, version)
            env.prepare()

    def _start(self):

        # 先下载frida server，然后把server推送到设备上
        if not self._device.is_file_exist(self._environ.remote_path):
            self._environ.prepare()
            _logger.info(f"Push frida server to remote: {self._environ.remote_path}")
            temp_path = self._device.get_storage_path("frida", self._environ.remote_name)
            self._device.push(self._environ.local_path, temp_path, log_output=True)
            self._device.sudo("mv", temp_path, self._environ.remote_path, log_output=True)
            self._device.sudo("chmod", "755", self._environ.remote_path, log_output=True)

        # 转发端口
        self._forward = self._device.forward(f"tcp:{self._local_port}", f"tcp:{self._remote_port}")

        try:
            # 创建软链
            self._device.sudo("mkdir", "-p", self._server_dir)
            self._device.sudo("ln", "-s", self._environ.remote_path, self._server_path)

            # 接下来新开一个进程运行frida server，并且输出一下是否出错
            self._device.sudo(
                self._device.get_safe_command([
                    self._server_path,
                    "-d", "fs-binaries",
                    "-l", f"0.0.0.0:{self._remote_port}",
                    "-D", "&"
                ]),
                ignore_errors=True,
                log_output=True,
            )
        finally:
            # 删除软连接
            self._device.sudo("rm", self._server_path, ignore_errors=True)

    def _stop(self):
        try:
            # 删除软连接
            self._device.sudo("rm", self._server_path, ignore_errors=True)
            # 就算杀死adb进程，frida server也不一定真的结束了，所以kill一下frida server进程
            process_name_lc = f"{self._server_prefix}*".lower()
            for process in self.enumerate_processes():
                if fnmatch.fnmatchcase(process.name.lower(), process_name_lc):
                    _logger.debug(f"Find frida server process({process.name}:{process.pid}), kill it")
                    self._device.sudo("kill", "-9", process.pid, ignore_errors=True)
        finally:
            # 把转发端口给移除了，不然会一直占用这个端口
            self._forward.stop()

    class Environ:

        def __init__(self, abi: str, version: str):
            cfg = config["ANDROID_TOOL_FRIDA_SERVER"].copy()
            cfg.update(version=version, abi=abi)

            self._download_url = cfg["url"].format(**cfg)
            self.local_name = cfg["name"].format(**cfg)
            self.local_path = resource.get_data_path("frida", self.local_name, create_parent=True)
            self.remote_name = "fs-{abi}-{version}".format(**cfg)
            self.remote_path = adb.Device.get_data_path(self.remote_name)

        def prepare(self):
            if os.path.exists(self.local_path):
                return
            _logger.info("Download frida server ...")
            with utils.UrlFile(self._download_url) as file:
                if os.path.exists(self.local_path):
                    return
                with lzma.open(file.save(), "rb") as read, open(self.local_path, "wb") as write:
                    shutil.copyfileobj(read, write)
                file.clear()
