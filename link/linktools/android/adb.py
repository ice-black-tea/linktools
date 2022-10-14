#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : adb.py
@time    : 2018/11/25
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

__all__ = ("AdbError", "Adb", "Device")

import json
import re
import subprocess
import warnings
from typing import Optional, Any

import linktools
from linktools import __name__ as module_name, utils, resource, tools, get_logger
from linktools.decorator import cached_property
from .struct import Package

logger = get_logger("android.adb")


class AdbError(Exception):

    def __init__(self, message: str):
        super().__init__(message.rstrip("\r\n"))


class Adb(object):
    _alive_status = ["bootloader", "device", "recovery", "sideload"]

    @classmethod
    def devices(cls, alive: bool = None) -> [str]:
        """
        获取所有设备列表
        :param alive: 只显示在线的设备
        :return: 设备号数组
        """
        devices = []
        result = cls.exec("devices")
        lines = result.splitlines()
        for i in range(1, len(lines)):
            splits = lines[i].split(maxsplit=1)
            if len(splits) >= 2:
                device, status = splits
                if alive is not None:
                    if alive == (status in cls._alive_status):
                        devices.append(device)
                else:
                    devices.append(device)

        return devices

    @classmethod
    def popen(cls, *args: [str], **kwargs) -> subprocess.Popen:
        return tools.adb.popen(*args, **kwargs)

    @classmethod
    def exec(cls, *args: [str], capture_output: bool = True, ignore_error: bool = False, **kwargs) -> str:
        """
        执行命令
        :param args: 命令
        :param capture_output: 捕获输出。对于需要返回结果的功能设置为True
        :param ignore_error: 忽略错误，报错不会抛异常
        :return: 如果是不是守护进程，返回输出结果；如果是守护进程，则返回Popen对象
        """
        process, out, err = tools.adb.exec(*args, capture_output=capture_output, **kwargs)
        if not ignore_error and process.returncode != 0 and not utils.is_empty(err):
            err = err.decode(errors='ignore')
            if not utils.is_empty(err):
                raise AdbError(err)
        return out.decode(errors='ignore') if out is not None else ""


class Device(object):

    def __init__(self, device_id: str = None):
        """
        :param device_id: 设备号
        """
        if device_id is None:
            devices = Adb.devices(alive=True)
            if len(devices) == 0:
                raise AdbError("no devices/emulators found")
            elif len(devices) > 1:
                raise AdbError("more than one device/emulator")
            self._device_id = next(iter(devices))
        else:
            self._device_id = device_id

    @property
    def config(self) -> dict:
        return linktools.config["ANDROID_TOOL_BRIDGE_APK"]

    @cached_property
    def id(self) -> str:
        """
        获取设备号
        :return: 设备号
        """
        return self._device_id

    @cached_property
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
        out = self.shell("echo", "-n", "${USER_ID}")
        uid = utils.int(out, default=default)
        if uid != default:
            return uid
        raise AdbError("unknown adb uid: %s" % out)

    def popen(self, *args: [str], **kwargs) -> subprocess.Popen:
        """
        执行命令
        :param args: 命令行参数
        :return: 打开的进程
        """
        args = ["-s", self.id, *args]
        return Adb.popen(*args, **kwargs)

    def exec(self, *args: [str], **kwargs) -> str:
        """
        执行命令
        :param args: 命令行参数
        :return: adb输出结果
        """
        args = ["-s", self.id, *args]
        return Adb.exec(*args, **kwargs)

    def shell(self, *args: [str], **kwargs) -> str:
        """
        执行shell
        :param args: shell命令
        :return: adb输出结果
        """
        args = ["-s", self.id, "shell", *args]
        return Adb.exec(*args, **kwargs)

    def sudo(self, *args: [str], **kwargs) -> str:
        """
        以root权限执行shell
        :param args: shell命令
        :return: adb输出结果
        """
        if self.uid != 0:
            args = ["-s", self.id, "shell", "su", "-c", *args]
        else:
            args = ["-s", self.id, "shell", *args]
        return Adb.exec(*args, **kwargs)

    def install(self, file_path: str, **kwargs) -> str:
        """
        安装apk
        :param file_path: apk文件路径
        :return: adb输出结果
        """
        args = ["-s", self.id, "install", file_path]
        return Adb.exec(*args, **kwargs)

    def uninstall(self, package_name: str, **kwargs) -> str:
        """
        卸载apk
        :param package_name: 包名
        :return: adb输出结果
        """
        args = ["-s", self.id, "uninstall", self.extract_package(package_name)]
        return Adb.exec(*args, **kwargs)

    def push(self, src: str, dst: str, **kwargs) -> str:
        """
        推送文件到设备
        :param src: 源文件
        :param dst: 目标文件
        :return: adb输出结果
        """
        args = ["-s", self.id, "push", src, dst]
        return Adb.exec(*args, **kwargs)

    def pull(self, src: str, dst: str, **kwargs) -> str:
        """
        拉取设备的文件
        :param src: 源文件
        :param dst: 目标文件
        :return: adb输出结果
        """
        args = ["-s", self.id, "pull", src, dst]
        return Adb.exec(*args, **kwargs)

    def forward(self, arg1, arg2, **kwargs) -> str:
        """
        端口转发
        :param arg1: 本地端口
        :param arg2: 设备端口
        :return: adb输出结果
        """
        args = ["-s", self.id, "forward", arg1, arg2]
        return Adb.exec(*args, **kwargs)

    def reverse(self, arg1, arg2, **kwargs) -> str:
        """
        端口转发
        :param arg1: 设备端口
        :param arg2: 本地端口
        :return: adb输出结果
        """
        args = ["-s", self.id, "reverse", arg1, arg2]
        return Adb.exec(*args, **kwargs)

    def call_agent(self, *args: [str], **kwargs) -> str:
        """
        调用辅助apk功能
        :param args: 参数
        :return: 输出结果
        """
        apk_name = self.config["name"]
        apk_md5 = self.config["md5"]
        main_class = self.config["main"]
        start_flag = f"__start_flag_{apk_md5}__"
        end_flag = f"__end_flag_{apk_md5}__"

        apk_path = resource.get_path(apk_name)
        target_dir = self.get_storage_path("apk", apk_md5)
        target_path = self.get_storage_path("apk", apk_md5, apk_name)

        capture_output = kwargs.setdefault("capture_output", True)

        # check apk path
        if not self.is_file_exist(target_path):
            self.shell("rm", "-rf", target_dir)
            self.push(apk_path, target_path)
            if not self.is_file_exist(target_path):
                raise AdbError("%s does not exist" % target_path)
        # set flag if necessary
        if capture_output:
            args = ["--start-flag", start_flag, "--end-flag", end_flag, *args]
        # call apk
        result = self.shell(
            "CLASSPATH=%s" % target_path,
            "app_process", "/", main_class, *args,
            **kwargs
        )
        # parse flag if necessary
        if capture_output:
            begin = result.find(start_flag)
            end = result.rfind(end_flag)
            if begin >= 0 and end >= 0:
                begin = begin + len(start_flag)
                result = result[begin: end]
            elif begin >= 0:
                begin = begin + len(start_flag)
                raise AdbError(result[begin:])
        return result

    def get_prop(self, prop: str, **kwargs) -> str:
        """
        获取属性值
        :param prop: 属性名
        :return: 属性值
        """
        self._ignore_invalid_argument(kwargs, "capture_output", False)
        self._ignore_invalid_argument(kwargs, "daemon", True)

        return self.shell("getprop", prop, **kwargs).rstrip()

    def set_prop(self, prop: str, value: str, **kwargs) -> str:
        """
        设置属性值
        :param prop: 属性名
        :param value: 属性值
        :return: adb输出结果
        """
        args = ["setprop", prop, value]
        return self.shell(*args, **kwargs).rstrip()

    def kill(self, package_name: str, **kwargs) -> str:
        """
        关闭进程
        :param package_name: 关闭的包名
        :return: adb输出结果
        """
        args = ["am", "kill", self.extract_package(package_name)]
        return self.shell(*args, **kwargs).rstrip()

    def force_stop(self, package_name: str, **kwargs) -> str:
        """
        关闭进程
        :param package_name: 关闭的包名
        :return: adb输出结果
        """
        args = ["am", "force-stop", self.extract_package(package_name)]
        return self.shell(*args, **kwargs).rstrip()

    def is_file_exist(self, path: str, **kwargs) -> bool:
        """
        文件是否存在
        :param path: 文件路径
        :return: 是否存在
        """
        self._ignore_invalid_argument(kwargs, "capture_output", False)
        self._ignore_invalid_argument(kwargs, "daemon", True)

        args = ["[", "-a", path, "]", "&&", "echo", "-n ", "1"]
        out = self.shell(*args, **kwargs)
        return utils.bool(utils.int(out, default=0), default=False)

    def get_current_package(self, **kwargs) -> str:
        """
        获取顶层包名
        :return: 顶层包名
        """
        self._ignore_invalid_argument(kwargs, "capture_output", False)
        self._ignore_invalid_argument(kwargs, "daemon", True)

        timeout_meter = utils.TimeoutMeter(kwargs.pop("timeout", None))
        if self.uid < 10000:
            args = ["dumpsys", "activity", "top", "|", "grep", "^TASK", "-A", "1", ]
            out = self.shell(*args, timeout=timeout_meter.get(), **kwargs)
            items = out.splitlines()[-1].split()
            if items is not None and len(items) >= 2:
                return items[1].split("/")[0].rstrip()
        # use agent instead of dumpsys
        out = self.call_agent("common", "--top-package", timeout=timeout_meter.get(), **kwargs)
        if not utils.is_empty(out):
            return out
        raise AdbError("can not fetch top package")

    def get_current_activity(self, **kwargs) -> str:
        """
        获取顶层activity名
        :return: 顶层activity名
        """
        self._ignore_invalid_argument(kwargs, "capture_output", False)
        self._ignore_invalid_argument(kwargs, "daemon", True)

        args = ["dumpsys", "activity", "top", "|", "grep", "^TASK", "-A", "1"]
        result = self.shell(*args, **kwargs)
        items = result.splitlines()[-1].split()
        if items is not None and len(items) >= 2:
            return items[1].rstrip()
        raise AdbError("can not fetch top activity")

    def get_apk_path(self, package: str, **kwargs) -> str:
        """
        获取apk路径
        :return: apk路径
        """
        self._ignore_invalid_argument(kwargs, "capture_output", False)
        self._ignore_invalid_argument(kwargs, "daemon", True)

        timeout_meter = utils.TimeoutMeter(kwargs.pop("timeout", None))
        if self.uid < 10000:
            out = self.shell("pm", "path", package, timeout=timeout_meter.get(), **kwargs)
            match = re.search(r"^.*package:[ ]*(.*)[\s\S]*$", out)
            if match is not None:
                return match.group(1).strip()
        obj = self.get_packages(package, simple=True, timeout=timeout_meter.get(), **kwargs)
        return utils.get_item(obj, 0, "sourceDir", default="")

    def get_package(self, package_name: str, **kwargs) -> Optional[Package]:
        self._ignore_invalid_argument(kwargs, "capture_output", False)
        self._ignore_invalid_argument(kwargs, "daemon", True)

        args = ["package", "--packages", package_name]
        objs = json.loads(self.call_agent(*args, **kwargs))
        return Package(objs[0]) if len(objs) > 0 else None

    def get_packages(self, *package_names: str, system: bool = None, simple: bool = None, **kwargs) -> [Package]:
        """
        获取包信息
        :param package_names: 需要匹配的所有包名，为空则匹配所有
        :param system: true只匹配系统应用，false只匹配非系统应用，为空则全匹配
        :param simple: 只获取基本信息
        :return: 包信息
        """
        self._ignore_invalid_argument(kwargs, "capture_output", False)
        self._ignore_invalid_argument(kwargs, "daemon", True)

        result = []
        agent_args = ["package"]
        if not utils.is_empty(package_names):
            agent_args.append("--packages")
            agent_args.extend(package_names)
        if system is True:
            agent_args.append("--system")
        elif system is False:
            agent_args.append("--non-system")
        if simple is True:
            agent_args.append("--simple")
        objs = json.loads(self.call_agent(*agent_args, **kwargs))
        for obj in objs:
            result.append(Package(obj))
        return result

    def get_packages_for_uid(self, *uids: int, simple: bool = None, **kwargs) -> [Package]:
        """
        获取指定uid包信息
        :param uids: 需要匹配的所有uid
        :param simple: 只获取基本信息
        :return: 包信息
        """
        self._ignore_invalid_argument(kwargs, "capture_output", False)
        self._ignore_invalid_argument(kwargs, "daemon", True)

        result = []
        agent_args = ["package"]
        if not utils.is_empty(uids):
            agent_args.append("--uids")
            agent_args.extend([str(uid) for uid in uids])
        if simple is True:
            agent_args.append("--simple")
        objs = json.loads(self.call_agent(*agent_args, **kwargs))
        for obj in objs:
            result.append(Package(obj))
        return result

    @classmethod
    def _get_safe_path(cls, path: str) -> str:
        temp = path
        while True:
            result = temp.replace("../", "..")
            if temp == result:
                return result
            temp = result

    @classmethod
    def get_storage_path(cls, *paths: [str]) -> str:
        """
        存储文件路径
        :param paths: 文件名
        :return: 路径
        """
        return "/sdcard/%s/%s" % (
            module_name,
            "/".join([cls._get_safe_path(o) for o in paths])
        )

    @classmethod
    def get_data_path(cls, *paths: [str]) -> str:
        """
        /data/local/tmp路径
        :param paths: 文件名
        :return: 路径
        """
        ""
        return "/data/local/tmp/%s" % (
            "/".join([cls._get_safe_path(o) for o in paths])
        )

    @classmethod
    def extract_package(cls, package_name) -> str:
        """
        获取可识别的包名
        :param package_name: 包名
        :return: 包名
        """
        match = re.search(r"([a-zA-Z_]\w*)+([.][a-zA-Z_]\w*)+", package_name)
        if match is not None:
            return match.group(0)
        return package_name

    @classmethod
    def _ignore_invalid_argument(cls, kwargs: dict, key: str, value: Any):
        if key in kwargs:
            if kwargs[key] == value:
                kwargs.pop(key)
                warnings.warn(f"invalid argument {key}={value}, ignored!", stacklevel=2)

    class _Redirect:

        def __init__(self, device: "Device", address: str, port: int):
            self.device = device
            self.target_address = address
            self.target_port = port
            self.remote_port = None

        def start(self):
            if not self.target_address:
                # 如果没有指定目标地址，则通过reverse端口访问
                self.remote_port = self.device.exec("reverse", f"tcp:0", f"tcp:{self.target_port}").strip()
                destination = f"127.0.0.1:{self.remote_port}"
                logger.debug(f"Not found redirect address, use {destination} instead")
            else:
                # 指定了目标地址那就直接用目标地址
                destination = f"{self.target_address}:{self.target_port}"
                logger.debug(f"Found redirect address {destination}")
            # 排除localhost
            self.device.sudo(
                "iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-o", "lo", "-j", "RETURN"
            )
            # 转发流量
            self.device.sudo(
                "iptables", "-t", "nat", "-A", "OUTPUT", "-p", "tcp", "-j", "DNAT", "--to-destination", destination
            )

        def stop(self):
            # 清空iptables -t nat配置
            utils.ignore_error(self.device.sudo, "iptables", "-t", "nat", "-F")
            # 如果占用reverse端口，则释放端口
            if self.remote_port:
                utils.ignore_error(self.device.exec, "reverse", "--remove", f"tcp:{self.remote_port}")

        def __enter__(self):
            self.stop()
            self.start()
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            self.stop()

    def redirect(self, address: str = None, port: int = 8080):
        """
        将手机流量重定向到本地指定端口
        :param address: 本地监听地址，不填默认本机
        :param port: 本地监听端口
        :return: 重定向对象
        """
        return self._Redirect(self, address, port)
