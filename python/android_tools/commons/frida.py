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
from collections import Callable

import colorama
import frida
from colorama import Fore

from .adb import device
from .utils import utils


def _log(tag: str, message: object, fore: Fore = None):
    log = '[{0}] {1}'.format(tag, str(message).replace('\n', '\n    '))
    if fore is not None:
        log = fore + log
    print(log)


class server(object):

    log = _log

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
            server.log("*", "Frida server is running ...")
            return True
        elif self._start():
            server.log("*", "Frida server is running ...")
            return True
        else:
            server.log("*", "Frida server failed to run ...")
            return False

    def _start(self) -> bool:
        server.log("*", "Start frida server ...")
        command = "'%s'" % self.server_target_file
        if self.device.uid != 0:
            command = "su -c '%s'" % self.server_target_file

        if not self.device.exist_file(self.server_target_file):
            if not os.path.exists(self.server_file):
                server.log("*", "Download frida server ...")
                tmp_path = tempfile.mktemp()
                utils.download(self.server_url, tmp_path)
                with lzma.open(tmp_path, "rb") as read, open(self.server_file, "wb") as write:
                    shutil.copyfileobj(read, write)
                os.remove(tmp_path)
            server.log("*", "Push frida server to %s" % self.server_target_file)
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


class helper(object):
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

        if __name__ == '__main__':
            frida_helper().run("com.hu.test", jscode=jscode)

    ----------------------------------------------------------------------

    js内置函数：

        /*
         * byte数组转字符串，如果转不了就返回null
         * :param bytes:       字符数组
         * :param charset:     字符集(可选)
         */
        function BytesToString(bytes, charset);

        /*
         * 输出当前调用堆栈
         */
        function PrintStack();

        /*
         * 调用当前函数，并输出参数返回值
         * :param object:      对象(一般直接填this)
         * :param arguments:   arguments(固定填这个)
         * :param showStack:   是否打印栈(默认为false，可不填)
         * :param showArgs:    是否打印参数(默认为false，可不填)
         */
        function CallMethod(object, arguments, showStack, showArgs);

        /*
         * 打印栈，调用当前函数，并输出参数返回值
         * :param object:      对象(一般直接填this)
         * :param arguments:   arguments(固定填这个)
         * :param show:        是否打印栈和参数(默认为true，可不填)
         */
        function PrintStackAndCallMethod(object, arguments, show);

        /*
         * hook native
         */
        Interceptor.attach(Module.findExportByName(null, 'xxxxxx'), {
            onEnter: function (args) {
                send("xxxxxx called from:\\n" +
                    Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join("\\n"));
            },
            onLeave: function (retval) {
                send("xxxxxx retval: " + retval);
            }
        });

        /*
         * 调用native函数
         * 例： CallStack callStack("ABCDEFG", 10);
         */
        var CallStackPtr = Module.findExportByName(null, '_ZN7android9CallStackC1EPKci');
        var CallStack = new NativeFunction(CallStackPtr, 'pointer', ['pointer', 'pointer', 'int']);
        var callStack = Memory.alloc(1000);
        var logtag = Memory.allocUtf8String("ABCDEFG");
        CallStack(callStack, logtag, 10);

    ----------------------------------------------------------------------
    """

    log = _log

    def __init__(self, device_id: str = None):
        """
        :param device_id: 设备号
        """
        colorama.init(True)
        self.sessions = []
        self.device = device(device_id)
        self.server = server(self.device.id)
        self.server.start()

    @staticmethod
    def on_message(message: object, data: object) -> None:
        """
        执行脚本回调函数
        """
        if utils.contain(message, 'type', 'send') and utils.contain(message, 'payload'):
            payload = message['payload']
            if utils.contain(payload, 'frida_stack'):
                helper.log('*', payload['frida_stack'], fore=Fore.LIGHTYELLOW_EX)
            elif utils.contain(payload, 'frida_method'):
                helper.log('*', payload['frida_method'], fore=Fore.LIGHTMAGENTA_EX)
            else:
                helper.log('*', payload)
        elif utils.contain(message, 'type', 'error') and utils.contain(message, 'stack'):
            helper.log('*', message['stack'], fore=Fore.RED)
        else:
            helper.log('?', message, fore=Fore.RED)

    def run_script(self, package: str, jscode: str, callback: Callable = None) -> None:
        """
        向指定包名的进程中注入并执行js代码
        :param package: 指定包名/进程名
        :param jscode: 注入的js代码
        :param callback: 消息回调，为None采用默认回调，on_message(message, data)
        :return: None
        """
        jscode = self._preset_jscode + jscode
        for process in self.get_processes(package):
            helper.log('*', 'Attach process: %s (%d)' % (process.name, process.pid))
            try:
                session = self.server.frida_device.attach(process.pid)
                script = session.create_script(jscode)
                script.on('message', helper.on_message if callback is None else callback)
                script.load()
                self.sessions.append(session)
            except Exception as e:
                helper.log('!', str(e), fore=Fore.RED)
        helper.log('*', 'Running ...')

    def detach_all(self) -> None:
        """
        结束所有会话
        :return: None
        """
        for session in self.sessions:
            session.detach()

    def get_processes(self, package) -> [_frida.Process]:
        """
        获取指定包名的所有进程
        :param package: 指定包名/进程名
        :return: 进程列表
        """
        processes = []
        for process in self.server.frida_device.enumerate_processes():
            if process.name.find(package) > -1:
                processes.append(process)
        return processes

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
                JavaString = Java.use('java.lang.String');
                Charset = Java.use('java.nio.charset.Charset');
            });

            /*
             * byte数组转字符串，如果转不了就返回null
             * bytes:       字符数组
             * charset:     字符集(可选)
             */
            function BytesToString(bytes, charset) {
                if (bytes !== undefined && bytes != null) {
                    charset = charset || Charset.defaultCharset();
                    var str = JavaString.$new.
                        overload('[B', 'java.nio.charset.Charset').
                        call(JavaString, bytes, charset).toString();
                    try {
                        return str.toString();
                    } catch(e) {
                        return null;
                    }
                } else {
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
             * object:      对象(一般直接填this)
             * arguments:   arguments(固定填这个)
             * showStack:   是否打印栈(默认为false，可不填)
             * showArgs:    是否打印参数(默认为false，可不填)
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
             * object:      对象(一般直接填this)
             * arguments:   arguments(固定填这个)
             * show:        是否打印栈和参数(默认为true，可不填)
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
                send({"frida_stack": body});
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
                send({"frida_method": body});
                return ret;
            }
        """.replace("\n", "")


if __name__ == '__main__':
    server().start()
