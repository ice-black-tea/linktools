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
from typing import Optional, Any

from .struct import Package, UnixSocket, InetSocket
from .. import utils, resource, tools, config, get_logger, ToolExecError
from ..decorator import cached_property
from ..version import __name__ as module_name

_logger = get_logger("android.adb")


class AdbError(Exception):
    pass


class Adb(object):
    _ALIVE_STATUS = ("bootloader", "device", "recovery", "sideload")

    @classmethod
    def devices(cls, alive: bool = None) -> ["Device"]:
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
                if alive is None:
                    devices.append(Device(device))
                elif alive == (status in cls._ALIVE_STATUS):
                    devices.append(Device(device))

        return devices

    @classmethod
    def popen(cls, *args: [Any], **kwargs) -> utils.Popen:
        return tools["adb"].popen(*args, **kwargs)

    @classmethod
    def exec(
            cls,
            *args: [Any],
            timeout: float = None,
            ignore_errors: bool = False,
            log_output: bool = False
    ) -> str:
        """
        执行命令
        :param args: 命令
        :param timeout: 超时时间
        :param ignore_errors: 忽略错误，报错不会抛异常
        :param log_output: 把输出打印到logger中
        :return: 如果是不是守护进程，返回输出结果；如果是守护进程，则返回Popen对象
        """
        try:
            return tools["adb"].exec(
                *args,
                timeout=timeout,
                ignore_errors=ignore_errors,
                log_output=log_output,
            )
        except ToolExecError as e:
            raise AdbError(e)


class Device(object):

    def __init__(self, id: str = None):
        """
        :param id: 设备号
        """
        if id is None:
            devices = Adb.devices(alive=True)
            if len(devices) == 0:
                raise AdbError("no devices/emulators found")
            elif len(devices) > 1:
                raise AdbError("more than one device/emulator")
            self._id = devices[0]._id
        else:
            self._id = id

    @cached_property
    def id(self) -> str:
        """
        获取设备号
        :return: 设备号
        """
        return self._id

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

    @cached_property
    def uid(self) -> int:
        """
        获取shell的uid
        :return: uid
        """
        default = -1
        out = self.shell("id", "-u")
        uid = utils.int(out, default=default)
        if uid != default:
            return uid
        raise AdbError("unknown adb uid: %s" % out)

    def popen(self, *args: [Any], **kwargs) -> utils.Popen:
        """
        执行命令
        :param args: 命令行参数
        :return: 打开的进程
        """
        args = ["-s", self.id, *args]
        return Adb.popen(*args, **kwargs)

    def exec(self, *args: [Any], **kwargs) -> str:
        """
        执行命令
        :param args: 命令行参数
        :return: adb输出结果
        """
        args = ["-s", self.id, *args]
        return Adb.exec(*args, **kwargs)

    def shell(self, *args: [Any], privilege: bool = False, **kwargs) -> str:
        """
        执行shell
        :param args: shell命令
        :param privilege: 是否以root权限运行
        :return: adb输出结果
        """
        args = ["shell", *args] \
            if not privilege or self.uid == 0 \
            else ["shell", "su", "-c", *args]
        return self.exec(*args, **kwargs)

    def sudo(self, *args: [Any], **kwargs) -> str:
        """
        以root权限执行shell
        :param args: shell命令
        :return: adb输出结果
        """
        kwargs["privilege"] = True
        return self.shell(*args, **kwargs)

    def install(self, *file_path: str, **kwargs) -> str:
        """
        安装apk
        :param file_path: apk文件路径
        :return: adb输出结果
        """
        return self.exec("install", *file_path, **kwargs)

    def uninstall(self, package_name: str, **kwargs) -> str:
        """
        卸载apk
        :param package_name: 包名
        :return: adb输出结果
        """
        return self.exec("uninstall", self.extract_package(package_name), **kwargs)

    def push(self, src: str, dst: str, **kwargs) -> str:
        """
        推送文件到设备
        :param src: 源文件
        :param dst: 目标文件
        :return: adb输出结果
        """
        return self.exec("push", src, dst, **kwargs)

    def pull(self, src: str, dst: str, **kwargs) -> str:
        """
        拉取设备的文件
        :param src: 源文件
        :param dst: 目标文件
        :return: adb输出结果
        """
        return self.exec("pull", src, dst, **kwargs)

    def forward(self, local: str, remote: str):
        """
        端口转发
        :param local: 本地端口
        :param remote: 远程端口
        :return: 可关闭对象
        """

        result = self.exec("forward", local, remote)
        if local == "tcp:0":
            local = f"tcp:{result}"

        _local = local.split(":", maxsplit=1)
        _remote = remote.split(":", maxsplit=1)

        # noinspection PyPropertyDefinition,PyMethodParameters
        class Stoppable(utils.Stoppable):
            local = property(fget=lambda _: _local)
            remote = property(fget=lambda _: _remote)

            def stop(_):
                self.exec("forward", "--remove", local, ignore_errors=True)

        return Stoppable()

    def reverse(self, remote: str, local: str) -> utils.Stoppable:
        """
        端口转发
        :param remote: 远程端口
        :param local: 本地端口
        :return: 可关闭对象
        """

        result = self.exec("reverse", remote, local)
        if remote == "tcp:0":
            remote = f"tcp:{result}"

        _local = local.split(":", maxsplit=1)
        _remote = remote.split(":", maxsplit=1)

        # noinspection PyPropertyDefinition,PyMethodParameters
        class Stoppable(utils.Stoppable):
            local = property(fget=lambda _: _local)
            remote = property(fget=lambda _: _remote)

            def stop(_):
                self.exec("reverse", "--remove", remote, ignore_errors=True)

        return Stoppable()

    def redirect(self, address: str = None, port: int = 8080, uid: int = None) -> utils.Stoppable:
        """
        将手机流量重定向到本地指定端口
        :param address: 本地监听地址，不填默认本机
        :param port: 本地监听端口
        :param uid: 监听目标uid
        :return: 重定向对象
        """

        remote_port = None

        if not address:
            # 如果没有指定目标地址，则通过reverse端口访问
            remote_port = self.exec("reverse", f"tcp:0", f"tcp:{port}").strip()
            destination = f"127.0.0.1:{remote_port}"
            _logger.debug(f"Not found redirect address, use {destination} instead")
        else:
            # 指定了目标地址那就直接用目标地址
            destination = f"{address}:{port}"
            _logger.debug(f"Found redirect address {destination}")

        # 配置iptables规则，首先清除之前的规则，然后再把流量转发到目标端口上
        self.sudo("iptables", "-t", "nat", "-F")

        args = ["-A", "OUTPUT", "-p", "tcp"]  # 添加一条tcp协议的转发规则
        args += ["!", "-o", "lo"]  # 过滤localhost
        if uid is not None:
            args += ["-m", "owner", "--uid-owner", uid]  # 指定要重定向流量的uid
        args += ["-j", "DNAT", "--to-destination", destination]  # 转发到指定端口
        self.sudo("iptables", "-t", "nat", *args)

        # noinspection PyMethodParameters
        class Stoppable(utils.Stoppable):

            def stop(_):
                # 清空iptables -t nat配置
                self.sudo("iptables", "-t", "nat", "-F", ignore_errors=True)
                # 如果占用reverse端口，则释放端口
                if remote_port:
                    self.exec("reverse", "--remove", f"tcp:{remote_port}", ignore_errors=True)

        return Stoppable()

    def get_prop(self, prop: str, **kwargs) -> str:
        """
        获取属性值
        :param prop: 属性名
        :return: 属性值
        """
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
        args = ["[", "-a", path, "]", "&&", "echo", "-n ", "1"]
        out = self.shell(*args, **kwargs)
        return utils.bool(utils.int(out, default=0), default=False)

    @property
    def agent_info(self) -> dict:
        return config["ANDROID_TOOL_BRIDGE_APK"]

    def init_agent(self):
        """
        初始化agent
        :return: agent路径
        """
        apk_name = self.agent_info["name"]
        apk_md5 = self.agent_info["md5"]

        apk_path = resource.get_asset_path(apk_name)
        target_dir = self.get_storage_path("apk", apk_md5)
        target_path = self.get_storage_path("apk", apk_md5, apk_name)

        # check apk path
        if not self.is_file_exist(target_path):
            self.shell("rm", "-rf", target_dir)
            self.push(apk_path, target_path)
            if not self.is_file_exist(target_path):
                raise AdbError("%s does not exist" % target_path)

        return target_path

    def call_agent(self, *args: [str], **kwargs) -> str:
        """
        调用辅助apk功能
        :param args: 参数
        :return: 输出结果
        """
        apk_md5 = self.agent_info["md5"]
        main_class = self.agent_info["main"]
        start_flag = f"__start_flag_{apk_md5}__"
        end_flag = f"__end_flag_{apk_md5}__"

        # call apk
        args = ["--start-flag", start_flag, "--end-flag", end_flag, *args]
        result = self.shell(
            "CLASSPATH=%s" % self.init_agent(),
            "app_process", "/", main_class, *args,
            **kwargs
        )

        begin = result.find(start_flag)
        end = result.rfind(end_flag)
        if begin >= 0 and end >= 0:
            begin = begin + len(start_flag)
            result = result[begin: end]
        elif begin >= 0:
            begin = begin + len(start_flag)
            raise AdbError(result[begin:])
        return result

    def get_current_package(self, **kwargs) -> str:
        """
        获取顶层包名
        :return: 顶层包名
        """
        timeout = utils.Timeout(kwargs.pop("timeout", None))
        if self.uid < 10000:
            args = ["dumpsys", "activity", "top", "|", "grep", "^TASK", "-A", "1", ]
            out = self.shell(*args, timeout=timeout, **kwargs)
            items = out.splitlines()[-1].split()
            if items is not None and len(items) >= 2:
                return items[1].split("/")[0].rstrip()
        # use agent instead of dumpsys
        out = self.call_agent("common", "--top-package", timeout=timeout, **kwargs)
        if not utils.is_empty(out):
            return out
        raise AdbError("can not fetch top package")

    def get_current_activity(self, **kwargs) -> str:
        """
        获取顶层activity名
        :return: 顶层activity名
        """
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
        timeout = utils.Timeout(kwargs.pop("timeout", None))
        if self.uid < 10000:
            out = self.shell("pm", "path", package, timeout=timeout, **kwargs)
            match = re.search(r"^.*package:[ ]*(.*)[\s\S]*$", out)
            if match is not None:
                return match.group(1).strip()
        obj = self.get_packages(package, simple=True, timeout=timeout, **kwargs)
        return utils.get_item(obj, 0, "sourceDir", default="")

    def get_package(self, package_name: str, **kwargs) -> Optional[Package]:
        """
        根据包名获取包信息
        :param package_name: 包名
        :return: 包信息
        """
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

    def get_tcp_sockets(self, **kwargs) -> [InetSocket]:
        """
        同netstat命令，获取设备tcp连接情况，需要读取/proc/net/tcp文件，高版本设备至少需要shell权限
        :return: tcp连接列表
        """
        return self._get_sockets(InetSocket, "--tcp-sock", **kwargs)

    def get_udp_sockets(self, **kwargs) -> [InetSocket]:
        """
        同netstat命令，获取设备udp连接情况，需要读取/proc/net/udp文件，高版本设备至少需要shell权限
        :return: udp连接列表
        """
        return self._get_sockets(InetSocket, "--udp-sock", **kwargs)

    def get_raw_sockets(self, **kwargs) -> [InetSocket]:
        """
        同netstat命令，获取设备raw连接情况，需要读取/proc/net/raw文件，高版本设备至少需要shell权限
        :return: raw连接列表
        """
        return self._get_sockets(InetSocket, "--raw-sock", **kwargs)

    def get_unix_sockets(self, **kwargs) -> [UnixSocket]:
        """
        同netstat命令，获取设备unix连接情况，需要读取/proc/net/unix文件，高版本设备至少需要shell权限
        :return: unix连接列表
        """
        return self._get_sockets(UnixSocket, "--unix-sock", **kwargs)

    def _get_sockets(self, type, command, **kwargs):
        result = []
        agent_args = ["network", command]
        objs = json.loads(self.call_agent(*agent_args, **kwargs))
        for obj in objs:
            result.append(type(obj))
        return result

    @classmethod
    def get_safe_path(cls, path: str) -> str:
        """
        过滤"../"关键字
        :param path: 原始路径
        :return: 过滤完"../"的路径
        """
        temp = path
        while True:
            result = temp.replace("../", "..")
            if temp == result:
                return result
            temp = result

    @classmethod
    def get_safe_command(cls, seq: [str]) -> str:
        """
        用双引号把命令包起来
        :param seq: 原命令
        :return: 双引号包起来的命令
        """
        return utils.list2cmdline(seq)

    @classmethod
    def get_storage_path(cls, *paths: [str]) -> str:
        """
        存储文件路径
        :param paths: 文件名
        :return: 路径
        """
        return "/sdcard/%s/%s" % (
            module_name,
            "/".join([cls.get_safe_path(o) for o in paths])
        )

    @classmethod
    def get_data_path(cls, *paths: [str]) -> str:
        """
        /data/local/tmp路径
        :param paths: 文件名
        :return: 路径
        """
        return "/data/local/tmp/%s" % (
            "/".join([cls.get_safe_path(o) for o in paths])
        )

    @classmethod
    def extract_package(cls, package_name) -> str:
        """
        获取可识别的包名（主要是过滤像":"这类字符）
        :param package_name: 包名
        :return: 包名
        """
        match = re.search(r"([a-zA-Z_]\w*)+([.][a-zA-Z_]\w*)+", package_name)
        if match is not None:
            return match.group(0)
        return package_name

    def __repr__(self):
        return f"AndroidDevice<{self.id}>"
