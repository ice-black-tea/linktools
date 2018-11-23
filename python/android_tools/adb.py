#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re

from .utils import utils, _process


class AdbError(Exception):

    def __init__(self, message: str):
        Exception.__init__(self, message)


class adb(object):

    @staticmethod
    def devices() -> [str]:
        """
        获取所有设备列表
        :return: 设备号数组
        """
        result = adb.exec("devices")
        devices = result.partition('\n')[2].replace('\n', '').split('\tdevice')
        return [d for d in devices if len(d) > 2]

    @staticmethod
    def exec(*args: [str], capture_output: bool = True) -> str:
        """
        执行命令
        :param args: 命令
        :param capture_output: 捕获输出，填False使用标准输出
        :param background: 是否后台运行
        :return: 输出结果
        """
        if len(args) == 0:
            raise AdbError("args cannot be empty")
        command = "adb "
        for arg in args:
            command = command + adb._filter(arg) + " "
        stdout, stderr = None, None
        if capture_output is True:
            stdout, stderr = utils.PIPE, utils.PIPE
        process = utils.exec(command, stdin=None, stdout=stdout, stderr=stderr)
        if not utils.is_empty(process.err):
            raise AdbError(process.err)
        return process.out

    @staticmethod
    def _filter(arg: str) -> str:
        return "\"" + arg.replace("\\", "\\\\").replace("\"", "\\\"") + "\""


class device(object):

    def __init__(self, device_id: str = None):
        """
        :param device_id: 设备号
        """
        device_ids = adb.devices()
        if device_id is None:
            if len(device_ids) == 0:
                raise AdbError("no devices/emulators found")
            elif len(device_ids) > 1:
                raise AdbError("more than one device/emulator")
            self._device_id = device_ids[0]
        else:
            if not utils.is_contain(device_ids, device_id):
                raise AdbError("no device %s found" % device_id)
            self._device_id = device_id

    @property
    def id(self) -> str:
        """
        获取设备号
        :return: 设备号
        """
        return self._device_id

    @property
    def abi(self) -> str:
        """
        获取设备abi类型
        :return: abi类型
        """
        result = self.get_prop("ro.product.cpu.abi")
        if result.find("arm64") >= 0:
            return "arm64"
        elif result.find("armeabi") >= 0:
            return "arm"
        elif result.find("x86_64") >= 0:
            return "x86_64"
        elif result.find("x86") >= 0:
            return "x86"
        raise AdbError("unknown abi: %s" % result)

    @property
    def uid(self) -> int:
        """
        获取shell的uid
        :return: uid
        """
        default = -1

        result = self.shell("echo -n ${USER_ID}")
        id = utils.int(result, default=default)
        if id != default:
            return id

        result = self.shell("id -u")
        id = utils.int(result, default=default)
        if id != default:
            return id

        pattern = re.compile(r"(?<=uid=)[\d]+")
        result = pattern.findall(result)
        if not utils.is_empty(result):
            id = utils.int(result[0], default=default)
        if id != default:
            return id

        raise AdbError("unknown adb uid: %s" % result)

    def exec(self, *args: [str], capture_output: bool = True) -> str:
        """
        执行命令
        :param args: 命令
        :param capture_output: 捕获输出，填False使用标准输出
        :param background: 是否后台运行
        :return: adb输出结果
        """
        command = ["-s", self.id]
        command += args
        return adb.exec(*command, capture_output=capture_output)

    def shell(self, command: str, capture_output: bool = True) -> str:
        """
        执行shell
        :param capture_output: 捕获输出，填False使用标准输出
        :param command: shell命令
        :param background: 是否后台运行
        :return: adb输出结果
        """
        return self.exec("shell", command, capture_output=capture_output)

    def get_prop(self, prop: str):
        """
        获取属性值
        :param prop: 属性名
        :return: 属性值
        """
        return self.shell("getprop %s" % prop).rstrip('\r\n')

    def set_prop(self, prop: str, value: str) -> str:
        """
        设置属性值
        :param prop: 属性名
        :param value: 属性值
        :return: 输出结果
        """
        return self.shell("setprop %s %s" % (prop, value))

    def kill(self, package_name) -> str:
        """
        关闭进程
        :param package_name: 关闭的包名
        :return: 输出结果
        """
        package_name = self._fix_package_name(package_name)
        return self.shell('am kill %s' % package_name)

    def force_stop(self, package_name) -> str:
        """
        关闭进程
        :param package_name: 关闭的包名
        :return: 输出结果
        """
        package_name = self._fix_package_name(package_name)
        return self.shell('am force-stop %s' % package_name)

    def exist_file(self, path) -> bool:
        """
        文件是否存在
        :param path: 文件路径
        :return: 是否存在
        """
        result = self.shell("[ -a %s ] && echo -n 1" % path)
        return utils.bool(utils.int(result, default=0), default=False)

    def top_package(self) -> str:
        """
        获取顶层包名
        :return: 顶层包名
        """
        result = self.shell("dumpsys activity top | grep '^TASK' | tail -n 1")

        items = result.split()
        if items is not None and len(items) >= 2:
            if items[1] == "null":
                return self.top_activity().split("/")[0]
            else:
                return items[1]

        raise AdbError("unknown package: %s" % result)

    def top_activity(self):
        """
        获取顶层activity名
        :return: 顶层activity名
        """
        result = self.shell("dumpsys activity top | grep '^TASK' -A 1 | tail -n 1")
        items = result.split()
        if items is not None and len(items) >= 2:
            return items[1]
        raise AdbError("unknown activity: %s" % result)

    def jdb_connect(self, pid: str, port: str = "8699") -> _process:
        """
        连接jdb，取消等待调试器附加状态，让应用继续运行
        :param pid: 进程号
        :param port: 端口号
        :return: jdb子进程
        """
        self.exec("forward", "tcp:%s" % port, "jdwp:%s" % pid)
        jdb_command = "jdb -connect com.sun.jdi.SocketAttach:hostname=127.0.0.1,port=%s" % port
        return utils.exec(jdb_command, stdin=utils.PIPE, stdout=utils.PIPE, stderr=None)

    @staticmethod
    def _fix_package_name(package_name) -> str:
        index = package_name.find(":")
        if index == -1:
            return package_name
        return package_name[0:index]
