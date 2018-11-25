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

import lzma
import os
import shutil
import sys
import tempfile
import time
from concurrent.futures import thread
from collections import Callable

import _frida
import colorama
import frida
from colorama import Fore

from .adb import device
from .utils import utils


class server:

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
                utils.download(self.server_url, tmp_path)
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


class helper:
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
         * byte数组转字符串，如果转不了就返回byte[]
         * bytes:       字符数组
         * charset:     字符集(可选)
         */
        function BytesToString(bytes, charset);

        /*
         * 输出当前调用堆栈
         */
        function PrintStack();

        /*
         * 调用当前函数，并输出参数返回值
         * object:      对象(一般直接填this)
         * arguments:   arguments(固定填这个)
         * showStack:   是否打印栈(默认为false，可不填)
         * showArgs:    是否打印参数(默认为false，可不填)
         */
        function CallMethod(object, arguments, showStack, showArgs);

        /*
         * 打印栈，调用当前函数，并输出参数返回值
         * object:      对象(一般直接填this)
         * arguments:   arguments(固定填这个)
         * show:        是否打印栈和参数(默认为true，可不填)
         */
        function PrintStackAndCallMethod(object, arguments, show)

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

    def __init__(self, device_id: str = None):
        """
        :param device_id: 设备号
        """
        colorama.init(True)
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
                print(Fore.LIGHTYELLOW_EX + helper._format('*', payload['frida_stack']))
            elif utils.contain(payload, 'frida_method'):
                print(Fore.LIGHTMAGENTA_EX + helper._format('*', payload['frida_method']))
            else:
                print(helper._format('*', payload))
        elif utils.contain(message, 'type', 'error') and utils.contain(message, 'stack'):
            print(Fore.RED + helper._format('*', message['stack']))
        else:
            print(str(message))

    def run_script(self, package: str, jscode: str, on_message: Callable = None) -> None:
        """
        向指定包名的进程中注入并执行js代码
        :param package: 指定包名/进程名
        :param jscode: 注入的js代码
        :param on_message: 消息回调，为None采用默认回调，on_message(message, data)
        :return: None
        """
        jscode = self._preset_jscode + jscode
        for process in self.get_processes(package):
            print('[*] Attach process: %s (%d)' % (process.name, process.pid))
            session = self.server.frida_device.attach(process.pid)
            script = session.create_script(jscode)
            script.on('message', helper.on_message if on_message is None else on_message)
            script.load()
        print('[*] Running ...')
        sys.stdin.read()

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

    @staticmethod
    def _format(tag: str, message: object):
        return '[{0}] {1}'.format(tag, str(message).replace('\n', '\n    '))

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
             * byte数组转字符串，如果转不了就返回byte[]
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
