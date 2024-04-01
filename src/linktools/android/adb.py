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
import time
from typing import Optional, Any, Generator, List

from .struct import Package, UnixSocket, InetSocket, Process
from .. import utils, environ
from ..decorator import cached_property, cached_classproperty
from ..device import BridgeError, Bridge, BaseDevice
from ..reactor import Stoppable

_logger = environ.get_logger("android.adb")


class AdbError(BridgeError):
    pass


class Adb(Bridge):

    def __init__(self, options: List[str] = None):
        super().__init__(
            tool=environ.get_tool("adb"),
            options=options,
            error_type=AdbError
        )

    def list_devices(self, alive: bool = None) -> Generator["Device", None, None]:
        """
        获取所有设备列表
        :param alive: 只显示在线的设备
        :return: 设备号数组
        """
        result = self.exec("devices")
        lines = result.splitlines()
        for i in range(1, len(lines)):
            splits = lines[i].split(maxsplit=1)
            if len(splits) >= 2:
                device, status = splits
                if alive is None:
                    yield Device(device, adb=self)
                elif alive == (status in ("bootloader", "device", "recovery", "sideload")):
                    yield Device(device, adb=self)


class Device(BaseDevice):

    def __init__(self, id: str = None, adb: Adb = None):
        """
        :param id: 设备号
        """
        self._adb = adb or Adb()
        if id is None:
            devices = tuple(self._adb.list_devices(alive=True))
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
    def name(self) -> str:
        """
        获取设备名
        :return: 设备名
        """
        return self.get_prop("ro.product.model", timeout=1)

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
        return self.get_uid()

    def popen(self, *args: [Any], **kwargs) -> utils.Process:
        """
        执行命令
        :param args: 命令行参数
        :return: 打开的进程
        """
        args = ["-s", self.id, *args]
        return self._adb.popen(*args, **kwargs)

    @utils.timeoutable
    def exec(self, *args: [Any], **kwargs) -> str:
        """
        执行命令
        :param args: 命令行参数
        :return: adb输出结果
        """
        args = ["-s", self.id, *args]
        return self._adb.exec(*args, **kwargs)

    def make_shell_args(self, *args: [Any], privilege: bool = False, user: str = None):
        cmd = utils.list2cmdline([str(arg) for arg in args])
        if privilege and self.uid != 0:
            args = ["shell", "su", "-c", cmd]
        elif user:
            args = ["shell", "su", user, "-c", cmd]
        else:
            args = ["shell", cmd]
        return args

    @utils.timeoutable
    def shell(self, *args: [Any], privilege: bool = False, user: str = None, **kwargs) -> str:
        """
        执行shell
        :param args: shell命令
        :param privilege: 是否以root权限运行
        :param user: 以指定user运行
        :return: adb输出结果
        """
        args = self.make_shell_args(*args, privilege=privilege, user=user)
        return self.exec(*args, **kwargs)

    @utils.timeoutable
    def sudo(self, *args: [Any], **kwargs) -> str:
        """
        以root权限执行shell
        :param args: shell命令
        :return: adb输出结果
        """
        kwargs["privilege"] = True
        return self.shell(*args, **kwargs)

    @utils.timeoutable
    def install(self, path_or_url: str, opts: [str] = (), **kwargs):
        """
        安装apk
        :param path_or_url: apk文件路径
        :param opts: 安装参数
        """
        apk_path = path_or_url
        if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
            environ.logger.info(f"Download file: {path_or_url}")
            file = environ.get_url_file(path_or_url)
            apk_path = file.save()
            environ.logger.info(f"Save file to local: {apk_path}")

        remote_path = self.get_data_path("apk", f"{int(time.time())}.apk")
        try:
            environ.logger.debug(f"Push file to remote: {remote_path}")
            self.push(apk_path, remote_path, **kwargs)
            if self.uid >= 10000:
                self.shell("am", "start", "--user", "0",
                           "-a", "android.intent.action.VIEW",
                           "-t", "application/vnd.android.package-archive",
                           "-d", "file://%s" % remote_path,
                           **kwargs)
            else:
                self.shell("pm", "install", *(opts or tuple()), remote_path,
                           **kwargs)
        finally:
            environ.logger.debug(f"Clear remote file: {remote_path}")
            self.shell("rm", remote_path, **kwargs)

    @utils.timeoutable
    def uninstall(self, package_name: str, **kwargs):
        """
        卸载apk
        :param package_name: 包名
        :return: adb输出结果
        """
        self.exec("uninstall", package_name, **kwargs)

    @utils.timeoutable
    def push(self, src: str, dst: str, **kwargs):
        """
        推送文件到设备
        :param src: 源文件
        :param dst: 目标文件
        :return: adb输出结果
        """
        self.exec("push", src, dst, **kwargs)

    @utils.timeoutable
    def pull(self, src: str, dst: str, **kwargs):
        """
        拉取设备的文件
        :param src: 源文件
        :param dst: 目标文件
        :return: adb输出结果
        """
        self.exec("pull", src, dst, **kwargs)

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
        class Forward(Stoppable):
            local = property(fget=lambda _: _local)
            remote = property(fget=lambda _: _remote)

            def stop(_):
                self.exec("forward", "--remove", local, ignore_errors=True)

        return Forward()

    def reverse(self, remote: str, local: str):
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
        class Reverse(Stoppable):
            local = property(fget=lambda _: _local)
            remote = property(fget=lambda _: _remote)

            def stop(_):
                self.exec("reverse", "--remove", remote, ignore_errors=True)

        return Reverse()

    def redirect(self, address: str = None, port: int = None, uid: int = None):
        """
        将手机流量重定向到本地指定端口
        :param address: 本地监听地址，不填默认本机
        :param port: 本地监听端口
        :param uid: 监听目标uid
        :return: 重定向对象
        """

        remote_port = None

        if not port:
            port = utils.pick_unused_port()

        if not address:
            # 如果没有指定目标地址，则通过reverse端口访问
            remote_port = self.exec("reverse", f"tcp:0", f"tcp:{port}").strip()
            address = "127.0.0.1"
            destination = f"{address}:{remote_port}"
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
        class Redirect(Stoppable):

            def __init__(self):
                self.local_port = port
                self.local_address = address
                self.remote_port = remote_port

            def stop(_):
                # 清空iptables -t nat配置
                self.sudo("iptables", "-t", "nat", "-F", ignore_errors=True)
                # 如果占用reverse端口，则释放端口
                if remote_port:
                    self.exec("reverse", "--remove", f"tcp:{remote_port}", ignore_errors=True)

        return Redirect()

    @utils.timeoutable
    def get_prop(self, prop: str, **kwargs) -> str:
        """
        获取属性值
        :param prop: 属性名
        :return: 属性值
        """
        return self.shell("getprop", prop, **kwargs).rstrip()

    @utils.timeoutable
    def set_prop(self, prop: str, value: str, **kwargs) -> str:
        """
        设置属性值
        :param prop: 属性名
        :param value: 属性值
        :return: adb输出结果
        """
        args = ["setprop", prop, value]
        return self.shell(*args, **kwargs).rstrip()

    @utils.timeoutable
    def start(self, package_name: str, activity_name: str = None, **kwargs) -> str:
        """
        启动app的launcher页面
        :param package_name: 包名
        :param activity_name: activity名
        :return: adb输出结果
        """
        if not activity_name:
            package = self.get_package(package_name, **kwargs)
            activity = package.get_launch_activity()
            if not activity:
                raise AdbError(f"Package {package.name} does not have a launch activity")
            activity_name = activity.name

        return self.shell(
            "am", "start",
            "-a", "android.intent.action.MAIN",
            "-c", "android.intent.category.LAUNCHER",
            "-n", f"{package_name}/{activity_name}",
            **kwargs
        )

    @utils.timeoutable
    def kill(self, package_name: str, **kwargs) -> str:
        """
        关闭进程
        :param package_name: 关闭的包名
        :return: adb输出结果
        """
        args = ["am", "kill", package_name]
        return self.shell(*args, **kwargs).rstrip()

    @utils.timeoutable
    def force_stop(self, package_name: str, **kwargs) -> str:
        """
        关闭进程
        :param package_name: 关闭的包名
        :return: adb输出结果
        """
        args = ["am", "force-stop", package_name]
        return self.shell(*args, **kwargs).rstrip()

    @utils.timeoutable
    def is_file_exist(self, path: str, **kwargs) -> bool:
        """
        文件是否存在
        :param path: 文件路径
        :return: 是否存在
        """
        args = ["[", "-a", path, "]", "&&", "echo", "-n", "1"]
        out = self.shell(*args, **kwargs)
        return utils.bool(utils.int(out, default=0), default=False)

    @cached_classproperty
    def agent_info(self) -> dict:
        agent_info = environ.get_config("ANDROID_TOOL_BRIDGE_APK", type=dict)
        agent_info["start_flag"] = f"__start_flag_{agent_info['md5']}__"
        agent_info["end_flag"] = f"__end_flag_{agent_info['md5']}__"
        return agent_info

    @cached_property
    def agent_path(self) -> str:
        """
        初始化agent
        :return: agent路径
        """
        apk_name = self.agent_info["name"]
        apk_md5 = self.agent_info["md5"]

        apk_path = environ.get_asset_path(apk_name)
        target_dir = self.get_storage_path("apk", apk_md5)
        target_path = self.get_storage_path("apk", apk_md5, apk_name)

        # check apk path
        if not self.is_file_exist(target_path):
            self.shell("rm", "-rf", target_dir)
            self.push(apk_path, target_path)
            if not self.is_file_exist(target_path):
                raise AdbError("%s does not exist" % target_path)

        return target_path

    def make_agent_args(self, *args: [str], flag: bool = False) -> [str]:
        """
        生成agent参数
        :param args: 参数
        :param flag: 是否添加flag
        :return: 参数列表
        """
        agent_info = self.agent_info
        start_flag = agent_info["start_flag"]
        end_flag = agent_info["end_flag"]
        main_class = agent_info["main"]

        agent_args = [
            "CLASSPATH=%s" % self.agent_path,
            "app_process", "/", main_class,
        ]

        if flag:
            agent_args.extend([
                "--start-flag", start_flag,
                "--end-flag", end_flag
            ])

        agent_args.extend(args)

        return agent_args

    @utils.timeoutable
    def call_agent(self, *args: [str], **kwargs) -> str:
        """
        调用辅助apk功能
        :param args: 参数
        :return: 输出结果
        """
        agent_info = self.agent_info
        start_flag = agent_info["start_flag"]
        end_flag = agent_info["end_flag"]

        # call apk
        result = self.shell(
            *self.make_agent_args(*args, flag=True),
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

    @utils.timeoutable
    def get_current_package(self, **kwargs) -> str:
        """
        获取顶层包名
        :return: 顶层包名
        """
        if self.uid < 10000:
            args = ["dumpsys", "activity", "top", "|", "grep", "^TASK", "-A", "1", ]
            out = self.shell(*args, **kwargs)
            items = out.splitlines()[-1].split()
            if items is not None and len(items) >= 2:
                return items[1].split("/")[0].rstrip()
        # use agent instead of dumpsys
        out = self.call_agent("common", "--top-package", **kwargs)
        if not utils.is_empty(out):
            return out
        raise AdbError("can not fetch top package")

    @utils.timeoutable
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

    @utils.timeoutable
    def get_apk_path(self, package: str, **kwargs) -> str:
        """
        获取apk路径
        :return: apk路径
        """
        if self.uid < 10000:
            out = self.shell("pm", "path", package, **kwargs)
            match = re.search(r"^.*package:\s*(.*)[\s\S]*$", out)
            if match is not None:
                return match.group(1).strip()
        obj = self.get_packages(package, simple=True, **kwargs)
        return utils.get_item(obj, 0, "sourceDir", default="")

    @utils.timeoutable
    def get_uid(self, package_name: str = None, timeout: utils.Timeout = None) -> Optional[int]:
        """
        根据包名获取uid
        :param package_name: 包名
        :param timeout: 超时时间
        :return: uid
        """
        if package_name:
            info = self.get_package(package_name, simple=True, timeout=timeout)
            return info.user_id if info else None
        else:
            default = -1
            out = self.shell("id", "-u", timeout=timeout)
            uid = utils.int(out, default=default)
            if uid != default:
                return uid
            out = self.shell("echo", "-n", "${USER_ID}", timeout=timeout)
            uid = utils.int(out, default=default)
            if uid != default:
                return uid
            raise AdbError("unknown adb uid: %s" % out)

    @utils.timeoutable
    def get_package(self, package_name: str, simple: bool = None, **kwargs) -> Optional[Package]:
        """
        根据包名获取包信息
        :param package_name: 包名
        :param simple: 只获取基本信息
        :return: 包信息
        """
        args = ["package", "--packages", package_name]
        if simple is True:
            args.append("--simple")
        objs = json.loads(self.call_agent(*args, **kwargs))
        return Package(objs[0]) if len(objs) > 0 else None

    @utils.timeoutable
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

    @utils.timeoutable
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

    @utils.timeoutable
    def get_tcp_sockets(self, **kwargs) -> [InetSocket]:
        """
        同netstat命令，获取设备tcp连接情况，需要读取/proc/net/tcp文件，高版本设备至少需要shell权限
        :return: tcp连接列表
        """
        return self._get_sockets(InetSocket, "--tcp-sock", **kwargs)

    @utils.timeoutable
    def get_udp_sockets(self, **kwargs) -> [InetSocket]:
        """
        同netstat命令，获取设备udp连接情况，需要读取/proc/net/udp文件，高版本设备至少需要shell权限
        :return: udp连接列表
        """
        return self._get_sockets(InetSocket, "--udp-sock", **kwargs)

    @utils.timeoutable
    def get_raw_sockets(self, **kwargs) -> [InetSocket]:
        """
        同netstat命令，获取设备raw连接情况，需要读取/proc/net/raw文件，高版本设备至少需要shell权限
        :return: raw连接列表
        """
        return self._get_sockets(InetSocket, "--raw-sock", **kwargs)

    @utils.timeoutable
    def get_unix_sockets(self, **kwargs) -> [UnixSocket]:
        """
        同netstat命令，获取设备unix连接情况，需要读取/proc/net/unix文件，高版本设备至少需要shell权限
        :return: unix连接列表
        """
        return self._get_sockets(UnixSocket, "--unix-sock", **kwargs)

    @utils.timeoutable
    def _get_sockets(self, type, command, **kwargs):
        result = []
        agent_args = ["network", command]
        objs = json.loads(self.call_agent(*agent_args, **kwargs))
        for obj in objs:
            result.append(type(obj))
        return result

    @utils.timeoutable
    def get_processes(self, **kwargs) -> [Process]:
        result = []
        agent_args = ["process", "--list"]
        objs = json.loads(self.call_agent(*agent_args, **kwargs))
        for obj in objs:
            result.append(Process(obj))
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
    def get_storage_path(cls, *paths: [str]) -> str:
        """
        存储文件路径
        :param paths: 文件名
        :return: 路径
        """
        return "/sdcard/%s/%s" % (
            environ.name,
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

    def __repr__(self):
        return f"AndroidDevice<{self.id}>"
