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
import multiprocessing
import os
import shutil
import subprocess
import time
from pathlib import Path, PosixPath

import frida

import linktools
from linktools import resource, logger, utils
from linktools.android import adb
from linktools.decorator import cached_property

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


class AndroidFridaServer(FridaServer):

    def __init__(self, device: adb.Device, local_port: int = 47042, remote_port: int = 47042):
        super().__init__(frida.get_device_manager().add_remote_device(f"localhost:{local_port}"))
        self._device = device
        self._local_port = local_port
        self._remote_port = remote_port
        self._process: multiprocessing.Process = None

        # frida server文件相关参数
        self._download_url = self.config["url"]
        # local: {storage_path}/data/frida/frida-server-xxx
        self._local_path = Path(resource.get_data_path("frida", self.config["name"], create_parent=True))
        # android: {storage_path}/frida/frida-server-xxx
        self._remote_temp_path = PosixPath(self._device.get_storage_path()) / "frida" / self.config["name"]
        # android: /data/local/tmp/fs-xxx
        self._remote_path = PosixPath("/data/local/tmp") / "fs-{abi}-{version}".format(**self.config)

    @cached_property
    def config(self) -> dict:
        config = linktools.config["ANDROID_TOOL_FRIDA_SERVER"].copy()
        config["version"] = frida.__version__
        config["abi"] = self._device.abi
        config["url"] = config["url"].format(**config)
        config["name"] = config["name"].format(**config)
        return config

    @classmethod
    def _run_in_background(cls, device: adb.Device, path: str, port: int):
        try:
            device.sudo(path, "-l", f"0.0.0.0:{port}", stdin=subprocess.PIPE)
        except KeyboardInterrupt as e:
            pass
        except Exception as e:
            logger.error(e, tag="[!]")

    def _start(self):
        self._prepare()
        self._device.forward(f"tcp:{self._local_port}", f"tcp:{self._remote_port}")
        self._process = multiprocessing.Process(
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

        if self._device.is_file_exist(self._remote_path.as_posix()):
            return

        if not os.path.exists(self._local_path):
            logger.info("Download frida server ...", tag="[*]")
            tmp_file = resource.get_temp_path(self._local_path.name + ".tmp")
            utils.download(self._download_url, tmp_file)
            with lzma.open(tmp_file, "rb") as read, open(self._local_path, "wb") as write:
                shutil.copyfileobj(read, write)
            os.remove(tmp_file)

        logger.info(f"Push frida server to {self._remote_path}", tag="[*]")
        self._device.push(str(self._local_path), self._remote_temp_path.as_posix(), capture_output=False)
        self._device.sudo("mv", self._remote_temp_path.as_posix(), self._remote_path.as_posix(), capture_output=False)
        self._device.sudo("chmod", "755", self._remote_path)

    def _stop(self):
        try:
            process_name_lc = f"*{self._remote_path.name}*".lower()
            for process in [process for process in self.enumerate_processes() if
                            fnmatch.fnmatchcase(process.name.lower(), process_name_lc)]:
                self.kill(process.pid)
        finally:
            self._process = None


class IOSFridaServer(FridaServer):  # proxy for frida.core.Device
    __setattr__ = object.__setattr__

    def __init__(self, device: "tidevice.Device", local_port: int = 37042, remote_port: int = 27042):
        super().__init__(frida.get_device_manager().add_remote_device(f"localhost:{local_port}"))
        self._device = device
        self._local_port = local_port
        self._remote_port = remote_port
        self._process: multiprocessing.Process = None

    @classmethod
    def _run_in_background(cls, device: "tidevice.Device", local_port: int, remote_port: int):
        from tidevice._relay import relay, logger as _logger
        try:
            _logger.setLevel(logger.level)
            relay(device, local_port, remote_port)
        except KeyboardInterrupt:
            pass
        except Exception as e:
            logger.error(e, tag="[!]")

    def _start(self):
        self._process = multiprocessing.Process(
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
        try:
            if self._process is not None:
                self._process.kill()
                self._process.join(5)
        finally:
            self._process = None
