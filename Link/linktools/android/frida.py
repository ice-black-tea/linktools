#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : frida.py
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

import _frida
import _thread as thread
import lzma
import os
import shutil
import time

import colorama
import frida
from colorama import Fore

from linktools import __name__, utils, resource, logger
from linktools.android.adb import Device
from linktools.decorator import cached_property


class BaseHelper(object):

    def __init__(self, device_id: str = None):
        """
        :param device_id: 设备号
        """
        self.device = Device(device_id=device_id)
        self.frida_device = frida.get_device(self.device.id)

        self.server_name = self.config["name"].format(**self.config)
        self.server_url = self.config["url"].format(**self.config)
        self.server_file = resource.get_cache_path(self.server_name)
        self.server_target_file = "/data/local/tmp/%s/%s" % (__name__, self.server_name)

    @cached_property
    def config(self) -> dict:
        config = resource.get_config("android.json", "frida_server").copy()
        config["version"] = frida.__version__
        config["abi"] = self.device.abi
        return config

    def start_server(self) -> bool:
        """
        根据frida版本和设备abi类型下载并运行server
        :return: 运行成功为True，否则为False
        """
        if self.is_running():
            self.device.exec("forward", "tcp:27042", "tcp:27042")
            self.device.exec("forward", "tcp:27043", "tcp:27043")
            logger.info("Frida server is running ...", tag="[*]")
            return True
        elif self._start_server():
            self.device.exec("forward", "tcp:27042", "tcp:27042")
            self.device.exec("forward", "tcp:27043", "tcp:27043")
            logger.info("Frida server is running ...", tag="[*]")
            return True
        else:
            logger.info("Frida server failed to run ...", tag="[*]")
            return False

    def _start_server(self) -> bool:
        logger.info("Start frida server ...", tag="[*]")

        if not self.device.is_file_exist(self.server_target_file):
            if not os.path.exists(self.server_file):
                logger.info("Download frida server ...", tag="[*]")
                tmp_file = resource.get_cache_path(self.server_name + ".tmp")
                utils.download(self.server_url, tmp_file)
                with lzma.open(tmp_file, "rb") as read, open(self.server_file, "wb") as write:
                    shutil.copyfileobj(read, write)
                os.remove(tmp_file)
            logger.info("Push frida server to %s" % self.server_target_file, tag="[*]")
            self.device.exec("push", self.server_file, self.server_target_file, capture_output=False)
            self.device.shell("chmod 755 '%s'" % self.server_target_file)

        thread.start_new_thread(lambda: self.device.sudo(self.server_target_file, capture_output=False), ())
        time.sleep(1)
        return self.is_running()

    def kill_server(self) -> bool:
        """
        强制结束frida server
        :return: 结束成功为True，否则为False
        """

        logger.info("Kill frida server ...", tag="[*]")
        try:
            process = self.frida_device.get_process(self.server_name)
            if process is not None:
                self.device.sudo("kill", "-9", str(process.pid), capture_output=False)
                return True
        except frida.ServerNotRunningError:
            return True

        return False

    def is_running(self) -> bool:
        """
        判断服务端运行状态
        :return: 是否正在运行
        """
        try:
            self.frida_device.get_process(self.server_name)
            return True
        except frida.ServerNotRunningError:
            return False

    def get_process(self, name) -> _frida.Process:
        """
        通过进程名到的所有进程
        :param name: 进程名
        :return: 进程
        """
        return self.frida_device.get_process(name)

    def get_processes(self, package_name) -> [_frida.Process]:
        """
        根据包名匹配进程名
        :param package_name: 进程名（支持正则）
        :return: 进程列表
        """
        processes = []
        for process in self.frida_device.enumerate_processes():
            if self.device.fix_package_name(process.name) == package_name:
                processes.append(process)
        return processes


class FridaHelper(BaseHelper):
    """
    ----------------------------------------------------------------------

    eg.
        #!/usr/bin/env python3
        # -*- coding: utf-8 -*-

        from linktools import frida_helper

        jscode = \"\"\"
            var $ = new JavaHelper();
            var Clazz = Java.use("java.lang.Class");
            var HashMap = Java.use("java.util.HashMap");

            HashMap.put.implementation = function() {

                send("this.threshold = " + this.threshold.value);

                var clazz = Java.cast(this.getClass(), Clazz);
                var field = clazz.getDeclaredField("threshold");
                field.setAccessible(true);
                send("this.threshold = " + field.getInt(this));

                // call origin method
                var ret = $.callMethod(this, arguments);
                $.printStack();
                $.printArguments(arguments, ret);
                return ret;
            }
        \"\"\"

        if __name__ == "__main__":
            frida_helper().run_script("xxx.xxx.xxx", jscode)

    ----------------------------------------------------------------------
    """

    def __init__(self, device_id: str = None):
        """
        :param device_id: 设备号
        """
        super().__init__(device_id)
        self.sessions = []
        with open(resource.get_persist_path("android-frida.js"), "rt") as fd:
            self._pre_script_code = fd.read().replace("\n", "")
        self.on_init()

    def on_init(self) -> None:
        """
        初始化操作
        """
        colorama.init(True)
        self.start_server()

    def on_load(self, **kwargs) -> None:
        """
        脚本加载回调
        :param kwargs: process_id, process_name, session, script, script_code
        """
        pass

    def on_message(self, message: object, data: object, **kwargs) -> None:
        """
        消息回调函数
        :param message: 收到的消息
        :param data: 收到的数据
        :param kwargs: process_id, process_name, session, script, script_code
        """
        if utils.get_item(message, "type") == "send":
            payload = utils.get_item(message, "payload")

            stack = utils.get_item(payload, "stack")
            if not utils.is_empty(stack):
                del payload["stack"]
                logger.info(stack, tag="[*]", fore=Fore.CYAN)

            arguments = utils.get_item(payload, "arguments")
            if not utils.is_empty(arguments):
                del payload["arguments"]
                logger.info(arguments, tag="[*]", fore=Fore.LIGHTMAGENTA_EX)

            if not utils.is_empty(payload):
                logger.info(payload, tag="[*]")

        elif utils.get_item(message, "type") == "error" and utils.is_contain(message, "stack"):
            logger.info(utils.get_item(message, "stack"), tag="[*]", fore=Fore.RED)

        else:
            logger.info(message, tag="[?]", fore=Fore.RED)

    def on_destroyed(self, **kwargs) -> None:
        """
        脚本结束回调函数
        :param kwargs: process_id, process_name, session, script, script_code
        """
        pass

    def on_detached(self, reason: str, **kwargs) -> None:
        """
        会话结束回调函数，默认重启应用
        :param reason: 结束原因
        :param kwargs: process_id, process_name, session, script_code
        """
        session = kwargs["session"]
        process_id = kwargs["process_id"]
        process_name = kwargs["process_name"]
        script_code = kwargs["script_code"]

        logger.info("Detach process: %s (%d)" % (process_name, process_id), tag="[*]")

        if reason == "process-terminated" and not utils.is_contain(process_name, ":"):
            self.run_script(process_name, script_code, restart=True)
        if utils.is_contain(self.sessions, session):
            self.sessions.remove(session)

    def _run_script(self, process_id: int, process_name: str, script_code: str) -> _frida.Script:
        logger.info("Attach process: %s (%d)" % (process_name, process_id), tag="[*]")

        session = self.frida_device.attach(process_id)
        kwargs = {
            "session": session,
            "process_id": process_id,
            "process_name": process_name,
            "script_code": script_code,
        }
        session.on("detached", lambda reason: self.on_detached(reason, **kwargs))

        script = session.create_script(self._pre_script_code + script_code)
        kwargs = {
            "session": session,
            "script": script,
            "process_id": process_id,
            "process_name": process_name,
            "script_code": script_code,
        }
        script.on("message", lambda message, data: self.on_message(message, data, **kwargs))
        script.on("destroyed", lambda reason: self.on_destroyed(**kwargs))
        script.load()

        kwargs = {
            "session": session,
            "script": script,
            "process_id": process_id,
            "process_name": process_name,
            "script_code": script_code,
        }

        self.sessions.append(session)
        self.on_load(**kwargs)

        return script

    def run_script(self, package_name: str, script_code, restart: bool = False) -> [_frida.Script]:
        """
        向指定包名的进程中注入并执行js代码
        :param package_name: 需要注入的应用包名
        :param script_code: 注入的js代码
        :param restart: 是否重启应用
        :return: 脚本对象
        """
        scripts = []

        package_name = self.device.fix_package_name(package_name)

        if not restart:
            for process in self.get_processes(package_name):
                try:
                    script = self._run_script(process.pid, process.name, script_code)
                    scripts.append(script)
                except Exception as e:
                    logger.error(e, tag="[!]", fore=Fore.RED)
        else:
            try:
                process_id = self.frida_device.spawn([package_name])
                script = self._run_script(process_id, package_name, script_code)
                self.frida_device.resume(process_id)
                scripts.append(script)
            except Exception as e:
                logger.info(e, tag="[!]", fore=Fore.RED)

        logger.info("Running ...", tag="[*]")

        return scripts

    def detach_sessions(self) -> None:
        """
        结束所有会话
        """
        for session in self.sessions:
            try:
                session.detach()
            except:
                pass
        self.sessions.clear()
