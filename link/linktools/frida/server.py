#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : frida.py
@time    : 2021/12/18
@site    :
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
   /  oooooooooooooooo  .o.  oooo /,   \,"-----------
  / ==ooooooooooooooo==.o.  ooo= //   ,`\--{)B     ,"
 /_==__==========__==_ooo__ooo=_/'   /___________,"
"""
import abc
import fnmatch
import lzma
import os
import shutil
import subprocess
import time
from pathlib import PosixPath
from typing import Dict

import billiard
import frida

import linktools
from linktools import resource, logger, utils
from linktools.android import adb

try:
    import tidevice
except ModuleNotFoundError:
    pass


class FridaServer(utils.Proxy, metaclass=abc.ABCMeta):  # proxy for frida.core.Device
    __setattr__ = object.__setattr__

    def __init__(self, device: frida.core.Device):
        super().__init__(lambda: device)

    @property
    def is_running(self) -> bool:
        """
        判断服务端运行状态
        :return: 是否正在运行
        """
        try:
            processes = self.enumerate_processes()
            return processes is not None
        except (frida.TransportError, frida.ServerNotRunningError):
            return False

    def start(self) -> bool:
        """
        根据frida版本和设备abi类型下载并运行server
        :return: 运行成功为True，否则为False
        """
        if self.is_running:
            logger.info("Frida server is running ...", tag="[*]")
            return True

        logger.info("Start frida server ...", tag="[*]")
        self._start()
        for i in range(10):
            time.sleep(0.5)
            if self.is_running:
                logger.info("Frida server is running ...", tag="[*]")
                return True

        raise frida.ServerNotRunningError("Frida server failed to run ...")

    def stop(self) -> bool:
        """
        强制结束frida server
        :return: 结束成功为True，否则为False
        """
        logger.info("Kill frida server ...", tag="[*]")
        try:
            self._stop()
            return True
        except frida.ServerNotRunningError:
            return True
        except:
            return False

    @abc.abstractmethod
    def _start(self):
        pass

    @abc.abstractmethod
    def _stop(self):
        pass

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()


class FridaAndroidServer(FridaServer):

    def __init__(self, device: adb.Device = None, local_port: int = 47042, remote_port: int = 47042):
        super().__init__(frida.get_device_manager().add_remote_device(f"localhost:{local_port}"))
        self._device = device or adb.Device()
        self._local_port = local_port
        self._remote_port = remote_port
        self._process = None

        self._config = self._get_config(frida.__version__, device.abi)
        self._download_url = self._config["url"]
        self._local_path = resource.get_data_path("frida", self._config["name"], create_parent=True)  # 本机路径
        self._remote_path = PosixPath("/data/local/tmp") / "fs-{abi}-{version}".format(**self._config)  # 手机的路径

    @classmethod
    def setup(cls, abis=("arm", "arm64", "x86_64", "x86")):
        for abi in abis:
            config = cls._get_config(frida.__version__, abi)
            cls._download(
                config["url"],
                resource.get_data_path("frida", config["name"], create_parent=True)
            )

    @classmethod
    def _download(cls, url: str, path: str):
        if os.path.exists(path):
            return
        logger.info("Download frida server ...", tag="[*]")
        temp_path = resource.get_temp_path("frida-server-" + utils.get_md5(path))
        utils.download(url, temp_path)
        with lzma.open(temp_path, "rb") as read, open(path, "wb") as write:
            shutil.copyfileobj(read, write)
        os.remove(temp_path)

    @classmethod
    def _get_config(cls, version, abi) -> Dict[str, str]:
        config = linktools.config["ANDROID_TOOL_FRIDA_SERVER"].copy()
        config["version"] = version
        config["abi"] = abi
        config["url"] = config["url"].format(**config)
        config["name"] = config["name"].format(**config)
        return config

    @classmethod
    def _run_in_background(cls, device: adb.Device, path: str, port: int):
        try:
            device.sudo(path, "-d", "fs-binaries", "-l", f"0.0.0.0:{port}", stdin=subprocess.PIPE)
        except (KeyboardInterrupt, EOFError):
            pass
        except Exception as e:
            logger.error(e, tag="[!]")

    def _start(self):
        self._prepare()
        self._device.forward(f"tcp:{self._local_port}", f"tcp:{self._remote_port}")
        self._process = billiard.context.Process(
            target=self._run_in_background,
            args=(
                self._device,
                self._remote_path.as_posix(),
                self._remote_port,
            ),
            daemon=True
        )
        self._process.start()

    def _prepare(self):
        if not self._device.is_file_exist(self._remote_path.as_posix()):
            # 先下载
            self._download(self._download_url, self._local_path)
            # 再推送
            logger.info(f"Push frida server to {self._remote_path}", tag="[*]")
            temp_path = self._device.get_storage_path("frida", self._remote_path.name)
            self._device.push(str(self._local_path), temp_path, capture_output=False)
            self._device.sudo("mv", temp_path, self._remote_path.as_posix(), capture_output=False)
            self._device.sudo("chmod", "755", self._remote_path)

    def _stop(self):
        self._device.forward("--remove", f"tcp:{self._local_port}", ignore_error=True)

        if self._process is not None:
            utils.ignore_error(self._process.terminate)
            utils.ignore_error(self._process.join, 5)
            self._process = None

        process_name_lc = f"*{self._remote_path.name}*".lower()
        for process in self.enumerate_processes():
            if fnmatch.fnmatchcase(process.name.lower(), process_name_lc):
                self.kill(process.pid)


class FridaIOSServer(FridaServer):  # proxy for frida.core.Device
    __setattr__ = object.__setattr__

    def __init__(self, device: "tidevice.Device" = None, local_port: int = 37042, remote_port: int = 27042):
        super().__init__(frida.get_device_manager().add_remote_device(f"localhost:{local_port}"))
        self._device = device or tidevice.Device()
        self._local_port = local_port
        self._remote_port = remote_port
        self._process = None

    @classmethod
    def _run_in_background(cls, device: "tidevice.Device", local_port: int, remote_port: int):
        from tidevice._relay import relay, logger as _logger
        try:
            _logger.setLevel(logger.level)
            relay(device, local_port, remote_port)
        except (KeyboardInterrupt, EOFError):
            pass
        except Exception as e:
            logger.error(e, tag="[!]")

    def _start(self):
        self._process = billiard.context.Process(
            target=self._run_in_background,
            args=(
                self._device,
                self._local_port,
                self._remote_port,
            ),
            daemon=True
        )
        self._process.start()

    def _stop(self):
        if self._process is not None:
            utils.ignore_error(self._process.terminate)
            utils.ignore_error(self._process.join, 5)
            self._process = None
