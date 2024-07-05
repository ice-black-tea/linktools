#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Author    : HuJi <jihu.hj@alibaba-inc.com>
# Datetime  : 2022/2/25 6:45 PM
# User      : huji
# Product   : PyCharm
# Project   : link

import fnmatch
import json
import lzma
import os
import shutil
from typing import Optional, Dict, List

import frida

from .server import FridaServer
from .. import environ, utils
from .._url import DownloadHttpError
from ..android import Device
from ..decorator import cached_classproperty
from ..reactor import Stoppable

_logger = environ.get_logger("frida.server.android")


class AndroidFridaServer(FridaServer):
    """
    android server
    """

    def __init__(self, device: Device = None, local_port: int = 47042, remote_port: int = 47042, serve: bool = True):
        super().__init__(frida.get_device_manager().add_remote_device(f"localhost:{local_port}"))
        self._device = device or Device()
        self._local_port = local_port
        self._remote_port = remote_port
        self._forward: Optional[Stoppable] = None

        self._serve = serve
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

    def _start(self):

        try:
            # 转发端口
            if self._forward is not None:
                self._forward.stop()
            self._forward = self._device.forward(
                f"tcp:{self._local_port}",
                f"tcp:{self._remote_port}"
            )

            if self._serve:
                # 创建软链
                server_path = self._prepare_executable()
                self._device.sudo("mkdir", "-p", self._server_dir)
                self._device.sudo("ln", "-s", server_path, self._server_path)

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
            if self._serve:
                # 删除软连接
                self._device.sudo("rm", self._server_path, ignore_errors=True)

    def _stop(self):
        try:
            if self._serve:
                # 就算杀死adb进程，frida server也不一定真的结束了，所以kill一下frida server进程
                process_name_lc = f"{self._server_prefix}*".lower()
                for process in self._device.list_processes():
                    if fnmatch.fnmatchcase(process.name.lower(), process_name_lc):
                        _logger.debug(f"Find frida server process({process.name}:{process.pid}), kill it")
                        self._device.sudo("kill", "-9", process.pid, ignore_errors=True)
        finally:
            # 把转发端口给移除了，不然会一直占用这个端口
            if self._forward is not None:
                self._forward.stop()
                self._forward = None

    @cached_classproperty
    def _server_info(self) -> "List[Dict[str, str]]":
        server_path = environ.get_asset_path("android-frida.json")
        server_data = json.loads(utils.read_file(server_path, text=True))
        return server_data["FRIDA_SERVER"]

    @classmethod
    def _get_executables(cls, abi: str, version: str):
        result = []
        for config in cls._server_info:
            config = dict(config)
            config.update(version=version, abi=abi)
            min_version = config.get("min_version", "0.0.0")
            max_version = config.get("max_version", "99999.0.0")
            if utils.parse_version(min_version) <= utils.parse_version(version) <= utils.parse_version(max_version):
                result.append(cls.Executable(config))
        return result

    def _prepare_executable(self):
        executables = self._get_executables(self._device.abi, frida.__version__)

        # 先判断设备上有没有现成的frida server，有的话直接返回
        for executable in executables:
            remote_path = self._device.get_data_path("fs", executable.name)
            if self._device.is_file_exist(remote_path):
                return remote_path

        # 设备上如果没有，那需要下载了，默认按照配置里的顺序进行下载
        for executable in executables:
            remote_dir = self._device.get_data_path("fs")
            remote_path = self._device.get_data_path("fs", executable.name)

            # 先下载frida server，然后把server推送到设备上
            try:
                executable.download()
            except DownloadHttpError as e:
                if 400 <= e.code < 500:
                    continue
                raise e

            _logger.info(f"Push {executable.name} to remote: {remote_path}")

            temp_dir = self._device.get_data_path("temp")
            temp_path = self._device.push_file(executable.path, temp_dir, log_output=True)
            self._device.sudo("mkdir", "-p", remote_dir, log_output=True)
            self._device.sudo("mv", temp_path, remote_path, log_output=True)
            self._device.sudo("chmod", "755", remote_path, log_output=True)

            return remote_path

    @classmethod
    def setup(cls, abis: [str] = ("arm", "arm64", "x86_64", "x86"), version: str = frida.__version__):
        for abi in abis:
            for executable in cls._get_executables(abi, version):
                try:
                    executable.download()
                except DownloadHttpError as e:
                    if 400 <= e.code < 500:
                        continue
                    raise e
                break

    class Executable:

        def __init__(self, config: Dict[str, str]):
            self.url = config["url"].format(**config)
            self.name = config["name"].format(**config)
            self.path = environ.get_data_path("frida", self.name, create_parent=True)

        def download(self):
            if os.path.exists(self.path):
                return
            _logger.info("Download frida server ...")
            with environ.get_url_file(self.url) as file:
                if os.path.exists(self.path):
                    return
                with lzma.open(file.download(), "rb") as read, open(self.path, "wb") as write:
                    shutil.copyfileobj(read, write)
                file.clear()
