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
import subprocess
from pathlib import PosixPath

import billiard
import frida

import linktools
from linktools import resource, utils, logger
from linktools.android import adb
from linktools.frida import FridaServer


class FridaAndroidServer(FridaServer):
    """
    android server
    """

    def __init__(self, device: adb.Device = None, local_port: int = 47042, remote_port: int = 47042):
        super().__init__(frida.get_device_manager().add_remote_device(f"localhost:{local_port}"))
        self._device = device or adb.Device()
        self._local_port = local_port
        self._remote_port = remote_port
        self._environ = self.Environ(device.abi)
        self._process = None

    @classmethod
    def setup(cls, abis=("arm", "arm64", "x86_64", "x86")):
        for abi in abis:
            env = cls.Environ(abi)
            env.prepare()

    @classmethod
    def _run_in_background(cls, device: adb.Device, path: str, port: int):
        try:
            device.sudo(path, "-d", "fs-binaries", "-l", f"0.0.0.0:{port}", stdin=subprocess.PIPE)
        except (KeyboardInterrupt, EOFError):
            pass
        except Exception as e:
            logger.error(e, tag="[!]")

    def _start(self):
        # 先下载frida server，然后把server推送到设备上
        if not self._device.is_file_exist(self._environ.remote_path):
            self._environ.prepare()
            logger.info(f"Push frida server to {self._environ.remote_path}", tag="[*]")
            temp_path = self._device.get_storage_path("frida", self._environ.remote_name)
            self._device.push(self._environ.local_path, temp_path, capture_output=False)
            self._device.sudo("mv", temp_path, self._environ.remote_path, capture_output=False)
            self._device.sudo("chmod", "755", self._environ.remote_path)

        # 转发端口
        self._device.forward(f"tcp:{self._local_port}", f"tcp:{self._remote_port}")

        # 启动frida server
        self._process = billiard.context.Process(
            target=self._run_in_background,
            args=(
                self._device,
                self._environ.remote_path,
                self._remote_port,
            ),
            daemon=True
        )
        self._process.start()

    def _stop(self):
        # 先把转发端口给移除了，不然会一直占用这个端口
        self._device.forward("--remove", f"tcp:{self._local_port}", ignore_error=True)

        # 结束adb进程
        if self._process is not None:
            utils.ignore_error(self._process.terminate)
            utils.ignore_error(self._process.join, 5)
            self._process = None

        # 就算杀死adb经常，frida server也不一定真的结束了，所以kill一下frida server进程
        process_name_lc = f"*{self._environ.remote_name}*".lower()
        for process in self.enumerate_processes():
            if fnmatch.fnmatchcase(process.name.lower(), process_name_lc):
                self.kill(process.pid)

    class Environ:

        def __init__(self, abi, version=frida.__version__):
            config = linktools.config["ANDROID_TOOL_FRIDA_SERVER"].copy()
            config.setdefault("version", version)
            config.setdefault("abi", abi)

            self._download_url = config["url"].format(**config)
            self._temp_path = resource.get_temp_path(
                "download",
                utils.get_md5(self._download_url),
                utils.guess_file_name(self._download_url),
                create_parent=True
            )

            self.local_name = config["name"].format(**config)
            self.local_path = resource.get_data_path(
                "frida",
                self.local_name,
                create_parent=True
            )

            self.remote_name = "fs-{abi}-{version}".format(**config)
            self.remote_path = (PosixPath("/data/local/tmp") / self.remote_name).as_posix()

        def prepare(self):
            if not os.path.exists(self.local_path):
                logger.info("Download frida server ...", tag="[*]")
                utils.download(self._download_url, self._temp_path)
                with lzma.open(self._temp_path, "rb") as read, open(self.local_path, "wb") as write:
                    shutil.copyfileobj(read, write)
                os.remove(self._temp_path)
