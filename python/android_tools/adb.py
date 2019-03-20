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
import getpass

from .resource import resource
from .tools import tools
from .utils import Utils
from .version import __name__, __version__


class AdbError(Exception):

    def __init__(self, message: str):
        message = message.rstrip("\r\n")
        super().__init__(self, message)
        self.message = message

    def __str__(self):
        return self.message


class Adb(object):

    @staticmethod
    def devices(alive: bool = False) -> [str]:
        """
        获取所有设备列表
        :param alive: 只显示在线的设备
        :return: 设备号数组
        """
        devices = []
        result = Adb.exec("devices", capture_output=True)
        for line in result.partition("\n")[2].split("\n"):
            splits = line.split()
            if len(splits) >= 2:
                device = splits[0]
                status = splits[1]
                if not alive or status == "device":
                    devices.append(device)
        return devices

    @staticmethod
    def exec(*args: [str], capture_output: bool = True, **kwargs) -> str:
        """
        执行命令
        :param args: 命令
        :param capture_output: 捕获输出，填False使用标准输出
        :return: 输出结果
        """
        process = tools.adb.exec(*args, capture_output=capture_output, **kwargs)
        if process.returncode != 0 and not Utils.is_empty(process.err):
            raise AdbError(process.err)
        return process.out


class Device(object):

    @staticmethod
    def _get_tools_config() -> dict:
        if not hasattr(Device, "_tools_config"):
            setattr(Device, "_tools_config", resource.get_config("android_tools.json", "android_tools_apk"))
        return getattr(Device, "_tools_config")

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
        result = self.shell("echo", "-n", "${USER_ID}")
        uid = Utils.int(result, default=default)
        if uid != default:
            return uid
        raise AdbError("unknown adb uid: %s" % result)

    def exec(self, *args: [str], capture_output: bool = True, **kwargs) -> str:
        """
        执行命令
        :param args: 命令
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
        调用dex功能
        :param args: dex参数
        :param capture_output: 捕获输出，填False使用标准输出
        :return: dex输出结果
        """
        config = self._get_tools_config()
        apk_name = config["name"]
        main_class = config["main"]
        flag_begin = config["flag_begin"]
        flag_end = config["flag_end"]

        apk_path = resource.get_path(apk_name)
        target_dir = self.get_save_path("apk")
        target_path = self.get_save_path("apk", apk_name)

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
        return self.shell("getprop", prop).rstrip("\r\n")

    def set_prop(self, prop: str, value: str) -> str:
        """
        设置属性值
        :param prop: 属性名
        :param value: 属性值
        :return: adb输出结果
        """
        return self.shell("setprop", prop, value)

    def kill(self, package_name) -> str:
        """
        关闭进程
        :param package_name: 关闭的包名
        :return: adb输出结果
        """
        package_name = self._get_fix_package(package_name)
        return self.shell("am", "kill", package_name)

    def force_stop(self, package_name) -> str:
        """
        关闭进程
        :param package_name: 关闭的包名
        :return: adb输出结果
        """
        package_name = self._get_fix_package(package_name)
        return self.shell("am", "force-stop", package_name)

    def is_file_exist(self, path) -> bool:
        """
        文件是否存在
        :param path: 文件路径
        :return: 是否存在
        """
        result = self.shell("[", "-a", path, "]", "&&", "echo", "-n ", "1")
        return Utils.bool(Utils.int(result, default=0), default=False)

    def get_top_package(self) -> str:
        """
        获取顶层包名
        :return: 顶层包名
        """
        if self.uid < 10000:
            result = self.shell("dumpsys", "activity", "top", "|",
                                "grep", "^TASK", "-A", "1").rstrip("\r\n")
            items = result[result.rfind("\n"):].split()
            if items is not None and len(items) >= 2:
                return items[1].split("/")[0]
        # use dex instead of dumpsys
        result = self.call_tools("common", "--top-package")
        if not Utils.is_empty(result):
            return result
        raise AdbError("can not fetch top package")

    def get_top_activity(self) -> str:
        """
        获取顶层activity名
        :return: 顶层activity名
        """
        result = self.shell("dumpsys", "activity", "top", "|",
                            "grep", "^TASK", "-A", "1").rstrip("\r\n")
        items = result[result.rfind("\n"):].split()
        if items is not None and len(items) >= 2:
            return items[1]
        raise AdbError("can not fetch top activity")

    def get_apk_path(self, package: str) -> str:
        """
        获取apk路径
        :return: apk路径
        """
        if self.uid < 10000:
            return Utils.replace(self.shell("pm", "path", package), r"^.*:[ ]*|\r|\n", "")
        return self.call_tools("common", "--apk-path", package)

    def get_save_path(self, *paths: [str]) -> str:
        """
        存储文件路径
        :param paths: 文件名
        :return: 路径
        """
        return "/sdcard/%s/%s/%s" % (__name__, getpass.getuser(), "/".join(paths))

    # def jdb_connect(self, pid: str, port: str = "8699") -> _process:
    #     """
    #     连接jdb，取消等待调试器附加状态，让应用继续运行
    #     :param pid: 进程号
    #     :param port: 端口号
    #     :return: jdb子进程
    #     """
    #     self.exec("forward", "tcp:%s" % port, "jdwp:%s" % pid)
    #     jdb_command = "jdb -connect com.sun.jdi.SocketAttach:hostname=127.0.0.1,port=%s" % port
    #     return utils.exec(jdb_command, stdin=utils.PIPE, stdout=utils.PIPE, stderr=utils.PIPE)

    @staticmethod
    def _get_fix_package(package_name) -> str:
        index = package_name.find(":")
        if index == -1:
            return package_name
        return package_name[0:index]
