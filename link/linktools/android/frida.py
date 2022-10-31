#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Author    : HuJi <jihu.hj@alibaba-inc.com>
# Datetime  : 2022/2/25 6:45 PM
# User      : huji
# Product   : PyCharm
# Project   : link

__all__ = ("FridaAndroidServer",)

import fnmatch
import lzma
import os
import shutil

import frida

import linktools
from linktools import resource, get_logger, urlutils
from linktools.android import adb, AdbError
from linktools.frida import FridaServer

logger = get_logger("android.frida")


class FridaAndroidServer(FridaServer):
    """
    android server
    """

    def __init__(self, device: adb.Device = None, local_port: int = 47042, remote_port: int = 47042):
        super().__init__(frida.get_device_manager().add_remote_device(f"localhost:{local_port}"))
        self._device = device or adb.Device()
        self._local_port = local_port
        self._remote_port = remote_port
        self._environ = self.Environ(device.abi, frida.__version__)

    @classmethod
    def setup(cls, abis=("arm", "arm64", "x86_64", "x86"), version=frida.__version__):
        for abi in abis:
            env = cls.Environ(abi, version)
            env.prepare()

    def _start(self):
        # 先下载frida server，然后把server推送到设备上
        if not self._device.is_file_exist(self._environ.remote_path):
            self._environ.prepare()
            logger.info(f"Push frida server to remote: {self._environ.remote_path}")
            temp_path = self._device.get_storage_path("frida", self._environ.remote_name)
            self._device.push(self._environ.local_path, temp_path, capture_output=False)
            self._device.sudo("mv", temp_path, self._environ.remote_path, capture_output=False)
            self._device.sudo("chmod", "755", self._environ.remote_path)

        # 转发端口
        self._device.forward(f"tcp:{self._local_port}", f"tcp:{self._remote_port}")

        # 接下来新开一个进程运行frida server，并且输出一下是否出错
        try:
            self._device.sudo(
                self._environ.remote_path,
                "-d", "fs-binaries",
                "-l", f"0.0.0.0:{self._remote_port}",
                timeout=1,
                daemon=True,
            )
        except AdbError as e:
            logger.error(e)

    def _stop(self):
        try:
            # 就算杀死adb进程，frida server也不一定真的结束了，所以kill一下frida server进程
            process_name_lc = f"*{self._environ.remote_name}*".lower()
            for process in self.enumerate_processes():
                if fnmatch.fnmatchcase(process.name.lower(), process_name_lc):
                    self.kill(process.pid)
        finally:
            # 把转发端口给移除了，不然会一直占用这个端口
            self._device.forward("--remove", f"tcp:{self._local_port}", ignore_error=True)

    class Environ:

        def __init__(self, abi, version):
            config = linktools.config["ANDROID_TOOL_FRIDA_SERVER"].copy()
            config.update(version=version, abi=abi)

            self._download_url = config["url"].format(**config)
            self.local_name = config["name"].format(**config)
            self.local_path = resource.get_data_path("frida", self.local_name, create_parent=True)
            self.remote_name = "fs-{abi}-{version}".format(**config)
            self.remote_path = adb.Device.get_data_path(self.remote_name)

        def prepare(self):
            if os.path.exists(self.local_path):
                return
            logger.info("Download frida server ...")
            with urlutils.UrlFile(self._download_url) as file:
                if os.path.exists(self.local_path):
                    return
                with lzma.open(file.save(), "rb") as read, open(self.local_path, "wb") as write:
                    shutil.copyfileobj(read, write)
                file.clear()
