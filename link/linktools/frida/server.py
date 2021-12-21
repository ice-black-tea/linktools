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
import fnmatch
import lzma
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path, PosixPath
from typing import Optional

import _frida
import frida
from colorama import Fore

import linktools
from linktools import resource, logger, utils
from linktools.android import adb
from linktools.decorator import cached_property


class FridaServer(utils.Proxy):  # proxy for frida.core.Device
    __setattr__ = object.__setattr__

    def __init__(self, device: frida.core.Device):
        super().__init__(lambda: device)

    def start(self):
        raise NotImplemented()

    def stop(self):
        raise NotImplemented()

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

    def get_process(self, pid: int = None, process_name: str = None) -> Optional["_frida.Process"]:
        """
        通过进程名到的所有进程
        :param pid: 进程id
        :param process_name: 进程名
        :return: 进程
        """
        if process_name is not None:
            process_name = process_name.lower()
        for process in self.enumerate_processes():
            if pid is not None:
                if process.pid == pid:
                    return process
            elif process_name is not None:
                if fnmatch.fnmatchcase(process.name.lower(), process_name):
                    return process
        raise frida.ProcessNotFoundError(f"unable to find process with pid '{pid}', name '{process_name}'")

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()


class FridaAndroidServer(FridaServer):

    def __init__(self, device_id: str = None, local_port=47042, remote_port=47042):
        self._device = adb.Device(device_id=device_id)
        self._local_port = local_port
        self._remote_port = remote_port
        self._local_address = f"localhost:{self._local_port}"
        super().__init__(frida.get_device_manager().add_remote_device(self._local_address))

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

    def start(self) -> bool:
        """
        根据frida版本和设备abi类型下载并运行server
        :return: 运行成功为True，否则为False
        """
        if self._local_port is not None:
            self._device.forward(f"tcp:{self._local_port}", f"tcp:{self._remote_port}")

        if self.is_running():
            logger.info("Frida server is running ...", tag="[*]")
            return True

        logger.info("Start frida server ...", tag="[*]")

        self._prepare()
        threading.Thread(
            target=self._device.sudo,
            args=(
                self._remote_path.as_posix(),
                "-l", f"0.0.0.0:{self._remote_port}",
            ),
            kwargs=dict(
                stdin=subprocess.PIPE,
            ),
            daemon=True
        ).start()

        for i in range(10):
            time.sleep(0.5)
            if self.is_running():
                logger.info("Frida server is running ...", tag="[*]")
                return True

        raise frida.ServerNotRunningError("Frida server failed to run ...")

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
        self._device.sudo(f"chmod 755 {self._remote_path}")

    def stop(self) -> bool:
        """
        强制结束frida server
        :return: 结束成功为True，否则为False
        """

        logger.info("Kill frida server ...", tag="[*]")
        try:
            process = self.get_process(process_name=f"*{self._remote_path.name}*")
            self.kill(process.pid)
            return True
        except frida.ServerNotRunningError:
            return True
        except:
            return False

    def is_running(self) -> bool:
        """
        判断服务端运行状态
        :return: 是否正在运行
        """
        try:
            process = self.get_process(process_name=f"*{self._remote_path.name}*")
            return process is not None
        except (frida.TransportError, frida.ServerNotRunningError, frida.ProcessNotFoundError):
            return False
