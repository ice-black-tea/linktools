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
import json
import re
import subprocess

import linktools
from linktools import __name__, utils, resource, tools
from linktools.decorator import cached_property
from .struct import Package


class AdbError(Exception):

    def __init__(self, message: str):
        message = message.rstrip("\r\n")
        super().__init__(self, message)
        self.message = message

    def __str__(self):
        return self.message


class Adb(object):

    @classmethod
    def devices(cls, alive: bool = None) -> [str]:
        """
        获取所有设备列表
        :param alive: 只显示在线的设备
        :return: 设备号数组
        """
        devices = []
        result = cls.exec("devices", capture_output=True)
        lines = result.splitlines()
        for i in range(1, len(lines)):
            splits = lines[i].split()
            if len(splits) >= 2:
                device = splits[0]
                status = splits[1]
                if alive is True:
                    if status == "device":
                        devices.append(device)
                elif alive is False:
                    if status != "device":
                        devices.append(device)
                else:
                    devices.append(device)
        return devices

    @classmethod
    def popen(cls, *args: [str], **kwargs) -> subprocess.Popen:
        return tools.adb.popen(*args, **kwargs)

    @classmethod
    def exec(cls, *args: [str], capture_output: bool = True, **kwargs) -> str:
        """
        执行命令
        :param args: 命令
        :param capture_output: 捕获输出，填False使用标准输出
        :return: 输出结果
        """
        process, out, err = tools.adb.exec(*args, capture_output=capture_output, **kwargs)
        if process.returncode != 0 and not utils.is_empty(err):
            err = err.decode(errors='ignore')
            if utils.is_empty(err):
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
        result = self.shell("echo", "-n", "${USER_ID}")
        uid = utils.int(result, default=default)
        if uid != default:
            return uid
        raise AdbError("unknown adb uid: %s" % result)

    def popen(self, *args: [str], **kwargs) -> subprocess.Popen:
        """
        执行命令
        :param args: 命令行参数
        :return: 打开的进程
        """
        args = ["-s", self.id, *args]
        return Adb.popen(*args, **kwargs)

    def exec(self, *args: [str], capture_output: bool = True, **kwargs) -> str:
        """
        执行命令
        :param args: 命令行参数
        :param capture_output: 捕获输出，填False使用标准输出
        :return: adb输出结果
        """
        args = ["-s", self.id, *args]
        return Adb.exec(*args, capture_output=capture_output, **kwargs)

    def shell(self, *args: [str], capture_output: bool = True, **kwargs) -> str:
        """
        执行shell
        :param args: shell命令
        :param capture_output: 捕获输出，填False使用标准输出
        :return: adb输出结果
        """
        args = ["-s", self.id, "shell", *args]
        return Adb.exec(*args, capture_output=capture_output, **kwargs)

    def sudo(self, *args: [str], capture_output: bool = True, **kwargs) -> str:
        """
        以root权限执行shell
        :param args: shell命令
        :param capture_output: 捕获输出，填False使用标准输出
        :return: adb输出结果
        """
        if self.uid != 0:
            args = ["-s", self.id, "shell", "su", "-c", *args]
        else:
            args = ["-s", self.id, "shell", *args]
        return Adb.exec(*args, capture_output=capture_output, **kwargs)

    def call_tools(self, *args: [str], capture_output: bool = True, **kwargs) -> str:
        """
        调用辅助apk功能
        :param args: 参数
        :param capture_output: 捕获输出，填False使用标准输出
        :return: 输出结果
        """
        apk_name = self.config["name"]
        apk_md5 = self.config["md5"]
        main_class = self.config["main"]
        flag_begin = self.config["flag_begin"]
        flag_end = self.config["flag_end"]

        apk_path = resource.get_persist_path(apk_name)
        target_dir = self.get_storage_path("apk", apk_md5)
        target_path = self.get_storage_path("apk", apk_md5, apk_name)

        # check apk path
        if not self.is_file_exist(target_path):
            self.shell("rm", "-rf", target_dir)
            self.exec("push", apk_path, target_path)
            if not self.is_file_exist(target_path):
                raise AdbError("%s does not exist" % target_path)
        # set --add-flag if necessary
        if capture_output:
            args = ["--add-flag", *args]
        # call apk
        result = self.shell("CLASSPATH=%s" % target_path,
                            "app_process", "/", main_class, *args,
                            capture_output=capture_output, **kwargs)
        # parse flag if necessary
        if capture_output:
            begin = result.find(flag_begin)
            end = result.rfind(flag_end)
            if begin >= 0 and end >= 0:
                begin = begin + len(flag_begin)
                result = result[begin: end]
            elif begin >= 0:
                begin = begin + len(flag_begin)
                raise AdbError(result[begin:])
        return result

    def get_prop(self, prop: str) -> str:
        """
        获取属性值
        :param prop: 属性名
        :return: 属性值
        """
        return self.shell("getprop", prop).rstrip()

    def set_prop(self, prop: str, value: str) -> str:
        """
        设置属性值
        :param prop: 属性名
        :param value: 属性值
        :return: adb输出结果
        """
        return self.shell("setprop", prop, value).rstrip()

    def kill(self, package_name) -> str:
        """
        关闭进程
        :param package_name: 关闭的包名
        :return: adb输出结果
        """
        package_name = self.fix_package_name(package_name)
        return self.shell("am", "kill", package_name).rstrip()

    def force_stop(self, package_name) -> str:
        """
        关闭进程
        :param package_name: 关闭的包名
        :return: adb输出结果
        """
        package_name = self.fix_package_name(package_name)
        return self.shell("am", "force-stop", package_name).rstrip()

    def is_file_exist(self, path) -> bool:
        """
        文件是否存在
        :param path: 文件路径
        :return: 是否存在
        """
        result = self.shell("[", "-a", path, "]", "&&", "echo", "-n ", "1")
        return utils.bool(utils.int(result, default=0), default=False)

    def get_top_package_name(self) -> str:
        """
        获取顶层包名
        :return: 顶层包名
        """
        if self.uid < 10000:
            result = self.shell("dumpsys", "activity", "top", "|", "grep", "^TASK", "-A", "1")
            items = result.splitlines()[-1].split()
            if items is not None and len(items) >= 2:
                return items[1].split("/")[0].rstrip()
        # use dex instead of dumpsys
        result = self.call_tools("common", "--top-package")
        if not utils.is_empty(result):
            return result
        raise AdbError("can not fetch top package")

    def get_top_activity_name(self) -> str:
        """
        获取顶层activity名
        :return: 顶层activity名
        """
        result = self.shell("dumpsys", "activity", "top", "|", "grep", "^TASK", "-A", "1")
        items = result.splitlines()[-1].split()
        if items is not None and len(items) >= 2:
            return items[1].rstrip()
        raise AdbError("can not fetch top activity")

    def get_apk_path(self, package: str) -> str:
        """
        获取apk路径
        :return: apk路径
        """
        if self.uid < 10000:
            match = re.search(r"^.*package:[ ]*(.*)[\s\S]*$", self.shell("pm", "path", package))
            if match is not None:
                return match.group(1).strip()
        return utils.get_item(self.get_packages(package, basic_info=True), 0, "sourceDir", default="")

    def get_packages(self, *package_names, system=False, non_system=False, basic_info=False) -> [Package]:
        """
        获取包信息
        :param package_names: 需要匹配的所有包名，为空则匹配所有
        :param system: 只匹配系统应用
        :param non_system: 只匹配非系统应用
        :param basic_info: 只获取基本信息
        :return: 包信息
        """
        result = []
        dex_args = ["package"]
        if not utils.is_empty(package_names):
            dex_args.extend(["--packages", *package_names])
        if system:
            dex_args.append("--system")
        elif non_system:
            dex_args.append("--non-system")
        if basic_info:
            dex_args.append("--basic-info")
        objs = json.loads(self.call_tools(*dex_args, capture_output=True))
        for obj in objs:
            result.append(Package(obj))
        return result

    @classmethod
    def get_storage_path(cls, *paths: [str]) -> str:
        """
        存储文件路径
        :param paths: 文件名
        :return: 路径
        """
        return "/sdcard/%s/%s" % (__name__, "/".join(paths))

    @classmethod
    def fix_package_name(cls, package_name) -> str:
        """
        获取可识别的包名
        :param package_name: 包名
        :return: 包名
        """
        match = re.search(r"([a-zA-Z_][a-zA-Z0-9_]*)+([.][a-zA-Z_][a-zA-Z0-9_]*)+", package_name)
        if match is not None:
            return match.group(0)
        return package_name
