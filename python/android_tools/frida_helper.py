#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import _frida
import sys

import colorama
from colorama import Fore

from .adb import device
from .frida_server import frida_server
from .utils import utils


class frida_helper:
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
        self.server = frida_server(self.device.id)
        self.server.start()

    @staticmethod
    def on_message(message: object, data: object) -> None:
        """
        执行脚本回调函数
        """
        if utils.is_contain(message, 'type', 'send') and utils.is_contain(message, 'payload'):
            payload = message['payload']
            if utils.is_contain(payload, 'frida_stack'):
                print(Fore.LIGHTYELLOW_EX + frida_helper._format('*', payload['frida_stack']))
            elif utils.is_contain(payload, 'frida_method'):
                print(Fore.LIGHTMAGENTA_EX + frida_helper._format('*', payload['frida_method']))
            else:
                print(frida_helper._format('*', payload))
        elif utils.is_contain(message, 'type', 'error') and utils.is_contain(message, 'stack'):
            print(Fore.RED + frida_helper._format('*', message['stack']))
        else:
            print(str(message))

    def run_script(self, package: str, jscode: str, on_message=None) -> None:
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
            script.on('message', frida_helper.on_message if on_message is None else on_message)
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
