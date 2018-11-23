#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import shutil
import tempfile
import time
import lzma

import frida
import _frida
import _thread as thread

from .adb import device
from .utils import utils


class frida_server:

    def __init__(self, device_id: str = None):
        """
        :param device_id: 设备号
        """
        self.device = device(device_id=device_id)
        self.server_name = "frida-server-{0}-android-{1}".format(frida.__version__, self.device.abi)
        self.server_dir = os.path.join(os.path.expanduser('~'), ".frida")
        self.server_file = os.path.join(self.server_dir, self.server_name)
        self.server_url = "https://github.com/frida/frida/releases/download/{0}/{1}.xz".format(frida.__version__,
                                                                                               self.server_name)
        self.server_target_file = "/data/local/tmp/{0}".format(self.server_name)
        if not os.path.exists(self.server_dir):
            os.makedirs(self.server_dir)

    def start(self) -> bool:
        """
        根据frida版本和设备abi类型下载并运行server
        :return: 运行成功为True，否则为False
        """
        if self.is_running():
            print("[*] Frida server is running ...")
            return True
        else:
            if self._start():
                print("[*] Frida server is running ...")
                return True
            else:
                print("[*] Frida server failed to run ...")
                return False

    def _start(self) -> bool:
        print("[*] Start frida server ...")
        command = "'%s'" % self.server_target_file
        if self.device.uid != 0:
            command = "su -c '%s'" % self.server_target_file

        if not self.device.exist_file(self.server_target_file):
            if not os.path.exists(self.server_file):
                print("[*] Download frida server ...")
                tmp_path = tempfile.mktemp()
                utils.download_from_url(self.server_url, tmp_path)
                with lzma.open(tmp_path, "rb") as read, open(self.server_file, "wb") as write:
                    shutil.copyfileobj(read, write)
                os.remove(tmp_path)
            print("[*] Push frida server to %s" % self.server_target_file)
            self.device.exec("push", self.server_file, "/data/local/tmp/")
            self.device.shell("chmod 755 '%s'" % self.server_target_file)

        self.device.exec("forward", "tcp:27042", "tcp:27042")
        self.device.exec("forward", "tcp:27043", "tcp:27043")
        thread.start_new_thread(lambda d, c: d.shell(c, capture_output=False), (self.device, command))
        time.sleep(1)

        return self.is_running()

    def is_running(self) -> bool:
        """
        判断服务端运行状态
        :return: 是否正在运行
        """
        try:
            self.frida_device.enumerate_processes()
            return True
        except frida.ServerNotRunningError:
            return False
        except Exception as e:
            raise e

    @property
    def frida_device(self) -> _frida.Device:
        """
        获取frida设备对象
        :return: frida设备对象
        """
        return frida.get_device(self.device.id)


if __name__ == '__main__':
    frida_server().start()
