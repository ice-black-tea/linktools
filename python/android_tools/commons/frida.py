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
import tempfile
import time

import colorama
import frida
from colorama import Fore

from .adb import device
from .utils import utils
from .resource import resource
from .version import __name__


class base_helper(object):

    def __init__(self, device_id: str = None):
        """
        :param device_id: 设备号
        """
        server = resource.get_config("frida_server")
        self.device = device(device_id=device_id)
        self.frida_device = frida.get_device(self.device.id)
        self.server_name = server["name"].format(version=frida.__version__, abi=self.device.abi)
        self.server_url = server["url"].format(version=frida.__version__, abi=self.device.abi)
        self.server_file = resource.download_path(self.server_name)
        self.server_target_file = "/data/local/tmp/%s/%s" % (__name__, self.server_name)

    def on_log(self, tag: object, message: object, **kwargs):
        pass

    def start_server(self) -> bool:
        """
        根据frida版本和设备abi类型下载并运行server
        :return: 运行成功为True，否则为False
        """
        if self.is_running():
            self.device.exec("forward", "tcp:27042", "tcp:27042")
            self.device.exec("forward", "tcp:27043", "tcp:27043")
            self.on_log("*", "Frida server is running ...")
            return True
        elif self._start_server():
            self.device.exec("forward", "tcp:27042", "tcp:27042")
            self.device.exec("forward", "tcp:27043", "tcp:27043")
            self.on_log("*", "Frida server is running ...")
            return True
        else:
            self.on_log("*", "Frida server failed to run ...")
            return False

    def _start_server(self) -> bool:
        self.on_log("*", "Start frida server ...")
        command = "'%s'" % self.server_target_file
        if self.device.uid != 0:
            command = "su -c '%s'" % self.server_target_file

        if not self.device.exist_file(self.server_target_file):
            if not os.path.exists(self.server_file):
                self.on_log("*", "Download frida server ...")
                tmp_path = resource.download_path(self.server_name + ".tmp")
                utils.download(self.server_url, tmp_path)
                with lzma.open(tmp_path, "rb") as read, open(self.server_file, "wb") as write:
                    shutil.copyfileobj(read, write)
                os.remove(tmp_path)
            self.on_log("*", "Push frida server to %s" % self.server_target_file)
            self.device.exec("push", self.server_file, self.server_target_file, capture_output=False)
            self.device.shell("chmod 755 '%s'" % self.server_target_file)

        thread.start_new_thread(lambda d, c: d.shell(c, capture_output=False), (self.device, command))
        time.sleep(1)

        return self.is_running()

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
        except Exception as e:
            raise e

    def get_process(self, name) -> _frida.Process:
        """
        通过进程名到的所有进程
        :param name: 进程名
        :return: 进程
        """
        return self.frida_device.get_process(name)

    def get_processes(self, name) -> [_frida.Process]:
        """
        根据进程名通过正则表达式进行匹配
        :param name: 进程名（支持正则）
        :return: 进程列表
        """
        processes = []
        for process in self.frida_device.enumerate_processes():
            if utils.match(process.name, name):
                processes.append(process)
        return processes


class frida_helper(base_helper):
    """
    ----------------------------------------------------------------------

    eg.
        #!/usr/bin/env python3
        # -*- coding: utf-8 -*-

        from android_tools import frida_helper

        jscode = \"\"\"
        Java.perform(function () {
            var HashMap = Java.use("java.util.HashMap");
            HashMap.put.implementation = function() {
                return CallMethod(this, arguments, true, true);
            }
        });
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
        self.start_server()
        colorama.init(True)

    # noinspection PyMethodMayBeStatic
    def on_log(self, tag: object, message: object, **kwargs) -> None:
        """
        消息回调函数
        :param tag: 标签
        :param message: 收到的消息
        :param kwargs: 字体颜色（fore）
        """
        log = "[{0}] {1}".format(tag, str(message).replace("\n", "\n    "))
        if utils.contain(kwargs, "fore"):
            log = utils.item(kwargs, "fore") + log
        print(log)

    def on_message(self, process_id: int, process_name: str, message: object) -> None:
        """
        消息回调函数
        :param process_id: 进程号
        :param process_name: 进程名
        :param message: 收到的消息
        """
        type = utils.item(message, "type")
        payload = utils.item(message, "payload")
        stack = utils.item(message, "stack")
        if type == "send" and payload is not None:
            helper_stack = utils.item(payload, "helper_stack")
            helper_method = utils.item(payload, "helper_method")
            if helper_stack is not None:
                self.on_log("*", helper_stack, fore=Fore.BLUE)
            elif helper_method is not None:
                self.on_log("*", helper_method, fore=Fore.LIGHTMAGENTA_EX)
            else:
                self.on_log("*", payload)
        elif type == "error" and stack is not None:
            self.on_log("*", stack, fore=Fore.RED)
        else:
            self.on_log("?", message, fore=Fore.RED)

    def on_destroyed(self, process_id: int, process_name: str, session: _frida.Session) -> None:
        """
        脚本结束回调函数
        :param process_id: 进程号
        :param process_name: 进程名
        :param session: 会话
        """
        self.on_log("*", "Detach process: %s (%d)" % (process_name, process_id))
        if utils.contain(self.sessions, session):
            self.sessions.remove(session)

    def on_detached(self, process_id: int, process_name: str, session: _frida.Session, jscode: str, reason: str) -> None:
        """
        会话结束回调函数
        :param process_id: 进程号
        :param process_name: 进程名
        :param session: 会话
        :param jscode: js脚本
        :param reason: 结束原因
        """
        if reason == "process-terminated":
            self._run_script(process_id, process_name, jscode, restart=True)
        if utils.contain(self.sessions, session):
            self.sessions.remove(session)

    def _run_script(self, process_id: int, process_name: str, jscode: str, restart: bool = False) -> None:
        try:
            if restart:
                process_id = self.frida_device.spawn([process_name])
            self.on_log("*", "Attach process: %s (%d)" % (process_name, process_id))
            session = self.frida_device.attach(process_id)
            session.on("detached", lambda reason: self.on_detached(process_id, process_name, session, jscode, reason))
            script = session.create_script(jscode)
            script.on("message", lambda message, data: self.on_message(process_id, process_name, message))
            script.on("destroyed", lambda reason: self.on_destroyed(process_id, process_name, session))
            script.load()
            if restart:
                self.frida_device.resume(process_id)
            self.sessions.append(session)
        except Exception as e:
            self.on_log("!", str(e), fore=Fore.RED)

    def run_script(self, name: str, jscode: str, restart: bool = False) -> None:
        """
        向指定包名的进程中注入并执行js代码
        :param name: 进程名（支持正则）
        :param jscode: 注入的js代码
        :param restart: 是否重启应用
        :return: None
        """
        jscode = self._preset_jscode + jscode
        for process in self.get_processes(name):
            self._run_script(process.pid, process.name, jscode, restart)
        self.on_log("*", "Running ...")

    def detach_sessions(self) -> None:
        """
        结束所有会话
        :return: None
        """
        for session in self.sessions:
            session.detach()

    @property
    def _preset_jscode(self) -> str:
        """
        :return: 内置js函数
        """
        return """
            var Throwable = null;
            var JavaString = null;
            var Charset = null;
            Java.perform(function () {
                Throwable = Java.use("java.lang.Throwable");
                JavaString = Java.use("java.lang.String");
                Charset = Java.use("java.nio.charset.Charset");
            });

            /*
             * byte数组转字符串，如果转不了就返回null
             * :param bytes:       字符数组
             * :param charset:     字符集(可选)
             */
            function BytesToString(bytes, charset) {
                if (bytes === undefined || bytes == null) {
                    return null;
                }
                try {
                    charset = charset || Charset.defaultCharset();
                    return JavaString.$new
                        .overload("[B", "java.nio.charset.Charset")
                        .call(JavaString, bytes, charset).toString();
                } catch(e) {
                    return null;
                }
            }

            /*
             * 输出当前调用堆栈
             */
            function PrintStack() {
                __PrintStack(Throwable.$new().getStackTrace(), true);
            };

            /*
             * 调用当前函数，并输出参数返回值
             * :param object:      对象(一般直接填this)
             * :param arguments:   arguments(固定填这个)
             * :param showStack:   是否打印栈(默认为false，可不填)
             * :param showArgs:    是否打印参数(默认为false，可不填)
             */
            function CallMethod(object, arguments, showStack, showArgs) {
                showStack = showStack === true;
                showArgs = showArgs === true;
                var stackElements = Throwable.$new().getStackTrace();
                __PrintStack(stackElements, showStack);
                return __CallMethod(stackElements[0], object, arguments, showArgs);
            };

            /*
             * 打印栈，调用当前函数，并输出参数返回值
             * :param object:      对象(一般直接填this)
             * :param arguments:   arguments(固定填这个)
             * :param show:        是否打印栈和参数(默认为true，可不填)
             */
            function PrintStackAndCallMethod(object, arguments, show) {
                return CallMethod(object, arguments, show !== false, show !== false);
            }

            function __PrintStack(stackElements, showStack) {
                if (!showStack) {
                    return;
                }
                var body = "Stack: " + stackElements[0];
                for (var i = 0; i < stackElements.length; i++) {
                    body += "\\n    at " + stackElements[i];
                }
                send({"helper_stack": body});
            }

            function __CallMethod(stackElement, object, arguments, showArgs) {
                var args = "";
                for (var i = 0; i < arguments.length; i++) {
                    args += "arguments[" + i + "],";
                }
                var method = stackElement.getMethodName();
                if (method == "<init>") {
                    method = "$init";
                }
                var ret = eval("object." + method + "(" + args.substring(0, args.length - 1) + ")");
                if (!showArgs) {
                    return ret;
                }
                var body = "Method: " + stackElement;
                for (var i = 0; i < arguments.length; i++) {
                    body += "\\n    Arguments[" + i + "]: " + arguments[i];
                }
                if (ret !== undefined) {
                    body += "\\n    Return: " + ret;
                }
                send({"helper_method": body});
                return ret;
            }
        """.replace("\n", "")


if __name__ == "__main__":
    frida_helper().start_server()
