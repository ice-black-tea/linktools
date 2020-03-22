# Link Tools

工具集入口

## frida

### 方法1：运行frida hook脚本

如hook.py：
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from linktools.android.frida import FridaHelper

jscode = """
Java.perform(function () {

    var helper = new JavaHelper();
    var Clazz = Java.use("java.lang.Class");
    var HashMap = Java.use("java.util.HashMap");

    HashMap.put.implementation = function() {

        send("this.threshold = " + this.threshold.value);

        var clazz = Java.cast(this.getClass(), Clazz);
        var field = clazz.getDeclaredField("threshold");
        field.setAccessible(true);
        send("this.threshold = " + field.getInt(this));

        // call origin method
        var ret = helper.callMethod(this, arguments);
        helper.printStack();
        helper.printArguments(arguments, ret);
        return ret;
    }
});
"""

if __name__ == '__main__':
    FridaHelper().run_script("xxx.xxx.xxx", jscode)
    sys.stdin.read()
```


### 方法2：使用ATFrida.py (推荐)

注入js文件或js代码到指定进程，支持根据设备下载对应的frida-server，js文件实时加载，应用重启后注入等功能

```bash
$ ATFrida.py -h
usage: ATFrida.py [-h] [-v] [-s SERIAL] [-p PACKAGE] (-f FILE | -c CODE) [-r]

easy to use frida

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -s SERIAL, --serial SERIAL
                        use device with given serial
  -p PACKAGE, --package PACKAGE
                        target package [default top-level package]
  -f FILE, --file FILE  javascript file
  -c CODE, --code CODE  javascript code
  -r, --restart         inject after restart [default false]
```

如hook.js文件：
```javascript

Java.perform(function () {

    var $ = new JavaHelper();

    // [*] Hook method: java.lang.Integer Integer.valueOf(int)
    $.hookMethod("java.lang.Integer", "valueOf", ["int"], function(obj, args) {
        return this.apply(obj, args);
    });

    // [*] Hook method: java.lang.Integer Integer.valueOf(int)
    // [*] Hook method: java.lang.Integer Integer.valueOf(java.lang.String)
    // [*] Hook method: java.lang.Integer Integer.valueOf(java.lang.String, int)
    $.hookMethods("java.lang.Integer", "valueOf", function(obj, args) {
        return this.apply(obj, args);
    });

    // [*] Hook method: int Integer.undefined()
    // [*] Hook method: void Integer.Integer(int)
    // [*] Hook method: void Integer.Integer(java.lang.String)
    // [*] Hook method: int Integer.bitCount(int)
    // [*] ...
    // [*] Hook method: long Integer.longValue()
    // [*] Hook method: short Integer.shortValue()
    $.hookClass("java.lang.Integer", function(obj, args) {
        return this.apply(obj, args);
    });

    // hook HashMap.put, print stack and args
    $.hookMethods("java.util.HashMap", "put", $.getHookImpl(true /* print stack */, true /* print args */));

    // hook HashMap.put, print stack and args
    var HashMap = Java.use("java.util.HashMap");
    HashMap.put.implementation = function() {
        var ret = $.callMethod(this, arguments);
        $.printStack();
        $.printArguments(arguments, ret);
        return ret;
    }
});
```

在终端中运行
```bash
ATFrida.py -f hook.js
```

### 输出效果

![frida](resource/imgs/frida.png)


### js使用

内置JavaHelper类的成员函数

```javascript
/**
 * 获取java类的类对象
 * :param className:    java类名
 * :return:             类对象
 */
function findClass(className) {}

/**
 * 获取java类的类对象
 * :param classloader:  java类所在的ClassLoader
 * :param className:    java类名
 * :return:             类对象
 */
function findClass(classloader, className) {}

/**
 * 为method添加properties
 * :param method:       方法对象
 */
function addMethodProperties(method) {}

/**
 * hook指定方法对象
 * :param method:       方法对象
 * :param impl:         hook实现，如调用原函数： function(obj, args) { return this.apply(obj, args); }
 */
function hookMethod(method, impl) {}

/**
 * hook指定方法对象
 * :param clazz:        java类名/类对象
 * :param method:       java方法名/方法对象
 * :param signature:    java方法签名，为null表示不设置签名
 * :param impl:         hook实现，如调用原函数： function(obj, args) { return this.apply(obj, args); }
 */
function hookMethod(clazz, method, signature, impl) {}

/**
 * hook指定方法名的所有重载
 * :param clazz:        java类名/类对象
 * :param method:       java方法名
 * :param impl:         hook实现，如调用原函数： function(obj, args) { return this.apply(obj, args); }
 */
function hookMethods(clazz, methodName, impl) {}

/**
 * hook指定类的所有方法
 * :param clazz:        java类名/类对象
 * :param impl:         hook实现，如调用原函数： function(obj, args) { return this.apply(obj, args); }
 */
function hookClass(clazz, impl) {}

/**
 * 根据当前栈调用原java方法
 * :param obj:          java对象
 * :param args:         java参数
 * :return:             java方法返回值
 */
function callMethod(obj, args) {}

/**
 * 获取hook实现，调用愿方法并展示栈和返回值
 * :param printStack:   是否展示栈，默认为true
 * :param printArgs:    是否展示参数，默认为true
 * :return:             hook实现
 */
function getHookImpl(printStack, printArgs) {}

/**
 * 获取当前java栈
 * :param printStack:   是否展示栈，默认为true
 * :param printArgs:    是否展示参数，默认为true
 * :return:             java栈对象
 */
function getStackTrace() {}

/**
 * 打印当前栈
 */
function printStack() {}

/**
 * 打印当前栈
 * :param message:      回显的信息
 */
function printStack(message) {}

/**
 * 打印当前参数和返回值
 */
function printArguments(args, ret) {}

/**
 * 打印当前参数和返回值
 * :param message:      回显的信息
 */
function printArguments(message, args, ret) {}
```

hook native方法
```javascript
// xxxxxx为方法名
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
```

调用native方法
```javascript
// 如 CallStack callStack("ABCDEFG", 10);
var CallStackPtr = Module.findExportByName(null, '_ZN7android9CallStackC1EPKci');
var CallStack = new NativeFunction(CallStackPtr, 'pointer', ['pointer', 'pointer', 'int']);
var callStack = Memory.alloc(1000);
var logtag = Memory.allocUtf8String("ABCDEFG");
CallStack(callStack, logtag, 10);
```

## ATTopApp.py

显示顶层应用信息、获取顶层应用apk、截屏等

```bash
$ ATTopApp.py -h
usage: ATTopApp.py [-h] [-v] [-s SERIAL]
                     [--package | --activity | --path | --apk [path] |
                     --screen [path]]

show top-level app's basic information

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -s SERIAL, --serial SERIAL
                        use device with given serial
  --package             show top-level package name
  --activity            show top-level activity name
  --path                show top-level package path
  --apk [path]          pull top-level apk file
  --screen [path]       capture screen and pull file
```

## ATInetnt.py

打开设置界面、开发者选项界面、app设置界面、安装证书、打开浏览器链接等

```bash
$ ATInetnt.py -h
usage: ATInetnt.py [-h] [-v] [-s SERIAL]
                    (--setting | --setting-dev | --setting-dev2 | --setting-app [PACKAGE] | --setting-cert PATH | --browser URL)

common intent action

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -s SERIAL, --serial SERIAL
                        use device with given serial
  --setting             start setting activity
  --setting-dev         start development setting activity
  --setting-dev2        start development setting activity
  --setting-app [PACKAGE]
                        start application setting activity [default top-level
                        package]
  --setting-cert PATH   start cert installer activity and install cert (need
                        '/data/local/tmp' write permission)
  --browser URL         start browser activity and jump to url (need scheme,
                        such as https://antiy.cn)
```

## TGrep.py

正则匹配文件内容（含zip文件内容）

```bash
$ TGrep.py -h
usage: TGrep.py [-h] [-v] [-i] pattern [file [file ...]]

match files with regular expressions

positional arguments:
  pattern            regular expression
  file               target files path

optional arguments:
  -h, --help         show this help message and exit
  -v, --version      show program's version number and exit
  -i, --ignore-case  ignore case
```

## ATApp.py

展示app基本信息

```bash
$ ATApp.py -h
usage: ATApp.py [-h] [-v] [-s SERIAL] (-a | -t | -p pkg [pkg ...])
                 [-o field [field ...]]

fetch application info

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -s SERIAL, --serial SERIAL
                        use device with given serial
  -a, --all             fetch all apps
  -t, --top             fetch top-level app only
  -p pkg [pkg ...], --packages pkg [pkg ...]
                        fetch target apps
  -o field [field ...], --order-by field [field ...]
                        order by target field
```

### 输出效果

![apps](resource/imgs/apps.png)

## ATTools.py

读取[配置文件](resource/config/tools.json)，下载使用对应工具

```bash
$ ATTools.py 
usage: ATTools.py [-h]
                   {adb,apktool,baksmali,compact_dex_converter,fastboot,java,mipay_extract,smali,vdex_extractor}
```

## ATToolsBg.py

读取[配置文件](resource/config/tools.json)，下载后台使用对应工具

```bash
$ ATToolsBg.py 
usage: ATToolsBg.py [-h]
                   {adb,apktool,baksmali,compact_dex_converter,fastboot,java,mipay_extract,smali,vdex_extractor}
```


## ATCallTool.py

测试android-tools.dex时使用