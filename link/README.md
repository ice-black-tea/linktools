# Link Tools

## 1. 开始使用

### 1.1 依赖项

python & pip (3.5及以上): <https://www.python.org/downloads/>

### 1.2 安装

直接安装

```bash
# 也可以直接使用github上的最新版本："linktools @ git+https://github.com/ice-black-tea/Zelda.git#egg=linktools&subdirectory=link"
python3 -m pip install -U "linktools[frida,magic]" # 如果用不到frida可以不加frida
```

### 1.3 配置环境变量（可选）

添加“LINKTOOLS_SETTING”环境变量，值为python文件的绝对路径，如：

```bash
LINKTOOLS_SETTING="/Users/admin/.linktools/setting.cfg"
```

然后在setting.cfg中添加配置，如：

```python
# 下载的工具和其他缓存会默认存储在“~/.linktools/”目录下，可通过以下配置修改
SETTING_DATA_PATH = "/Users/admin/.linktools/data"
SETTING_TEMP_PATH = "/Users/admin/.linktools/temp"
```

## 2. 相关功能

### 2.1 通用功能（脚本前缀为ct-）

#### 2.1.1 ct-grep

正则匹配文件内容 (含解析zip、elf等格式）

```bash
$ ct-grep -h
usage: ct-grep [-h] [-v] [-i] pattern [file [file ...]]

match files with regular expressions

positional arguments:
  pattern            regular expression
  file               target files path

optional arguments:
  -h, --help         show this help message and exit
  -v, --version      show program's version number and exit
  -i, --ignore-case  ignore case
```

#### 2.1.2 ct-tools

读取[配置文件](https://raw.githubusercontent.com/ice-black-tea/Zelda/master/link/linktools/configs/general_tools.yml)，下载使用对应工具

```bash
$ ct-tools -h
usage: ct-tools [-h] [-v] [-d] ...

tools wrapper

positional arguments:
  {aapt,adb,apktool,baksmali,chromedriver,compact_dex_converter,dex2jar,fastboot,jadx,jadx-gui,java,mipay_extract,smali,vdex_extractor}

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -d, --daemon          run tools as a daemon
```


### 2.2 android相关功能（脚本前缀为at-）

#### 2.2.1 at-adb

若环境变量中存在adb，则直接执行，否则自动下载最新版本。该功能支持操作多台手机

#### 2.2.2 at-pidcat

集成了<https://github.com/JakeWharton/pidcat>，并且修复了中文字符宽度问题

#### 2.2.3 at-top

显示顶层应用信息、获取顶层应用apk、截屏等

```bash
$ at-top -h
usage: at-top [-h] [-v] [-s SERIAL]
                     [--package | --activity | --path | --apk [path] |
                     --screen [path]]

show current running app's basic information

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -s SERIAL, --serial SERIAL
                        use device with given serial
  --package             show current running package name
  --activity            show current running activity name
  --path                show current running package path
  --apk [path]          pull current running apk file
  --screen [path]       capture screen and pull file
```

#### 2.2.4 at-inetnt

打包了常用intent操作，支持如打开设置界面、开发者选项界面、app设置界面、安装证书、打开浏览器链接等功能

```bash
$ at-inetnt -h
usage: at-inetnt [-h] [-v] [-s SERIAL]
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
                        start application setting activity [default current running
                        package]
  --setting-cert PATH   start cert installer activity and install cert (need
                        '/data/local/tmp' write permission)
  --browser URL         start browser activity and jump to url (need scheme,
                        such as https://antiy.cn)
```

#### 2.2.5 at-app

通过执行agent调用pms读取app基本信息并展示，组件、权限等信息相对静态检测更为准确

```bash
$ at-app -h
usage: at-app [-h] [-v] [-s SERIAL] (-a | -t | -p pkg [pkg ...])
                 [-o field [field ...]]

fetch application info

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -s SERIAL, --serial SERIAL
                        use device with given serial
  -a, --all             fetch all apps
  -t, --top             fetch current running app only
  -p pkg [pkg ...], --packages pkg [pkg ...]
                        fetch target apps
  -o field [field ...], --order-by field [field ...]
                        order by target field
```

**输出效果**

![apps](https://raw.githubusercontent.com/ice-black-tea/Zelda/master/link/images/apps.png)

#### 2.2.6 at-frida

该功能旨在方便使用frida，可根据应用名注入js文件或js代码到指定进程。提供了以下特性：
1. 可以支持根据设备和本地安装的frida版本，自动下载并推送frida server到设备，启动frida server自动化完成
2. 监听了spawn进程变化情况，可以同时hook主进程和各个子进程
3. 监听js文件变化，实时加载
4. 注入了内置脚本，封装常用功能，如：过ssl pinning

```bash
$ at-frida -h
usage: at-frida [-h] [-v] [-s serial | -d | --emulator | -i index | -c ip[:port] | --last] [-p PACKAGE] [--spawn] [--regular] [-l SCRIPT] [-e CODE]

easy to use frida

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -p PACKAGE, --package PACKAGE
                        target package [default current running package]
  --spawn               inject after spawn [default false]
  --regular             regular match package name
  -l SCRIPT, --load SCRIPT
                        load SCRIPT
  -e CODE, --eval CODE  evaluate CODE

adb optional arguments:
  -s serial, --serial serial
                        use device with given serial (adb -s option)
  -d, --device          use USB device (adb -d option)
  --emulator            use TCP/IP device (adb -e option)
  -i index, --index index
                        use device with given index
  -c ip[:port], --connect ip[:port]
                        use device with TCP/IP
  --last                use last device
```

**1) 以命令行方式运行**

如 [android.js](https://raw.githubusercontent.com/ice-black-tea/Zelda/master/spear/test/android.js) 文件：

```javascript

Java.perform(function () {
    AndroidHelper.bypassSslPinning();

    // [*] Hook method: java.lang.Integer Integer.valueOf(int)
    JavaHelper.hookMethod("java.lang.Integer", "valueOf", ["int"], function(obj, args) {
        return this.apply(obj, args);
    });

    // [*] Hook method: java.lang.Integer Integer.valueOf(int)
    // [*] Hook method: java.lang.Integer Integer.valueOf(java.lang.String)
    // [*] Hook method: java.lang.Integer Integer.valueOf(java.lang.String, int)
    JavaHelper.hookMethods("java.lang.Integer", "valueOf", function(obj, args) {
        return this.apply(obj, args);
    });

    // [*] Hook method: int Integer.undefined()
    // [*] Hook method: void Integer.Integer(int)
    // [*] Hook method: void Integer.Integer(java.lang.String)
    // [*] Hook method: int Integer.bitCount(int)
    // [*] ...
    // [*] Hook method: long Integer.longValue()
    // [*] Hook method: short Integer.shortValue()
    JavaHelper.hookClass("java.lang.Integer", function(obj, args) {
        return this.apply(obj, args);
    });

    // hook HashMap.put, print stack and args
    JavaHelper.hookMethods("java.util.HashMap", "put", JavaHelper.getHookImpl({printStack: false, printArgs: true}));

    // hook HashMap.put, print stack and args
    var HashMap = Java.use("java.util.HashMap");
    HashMap.put.implementation = function() {
        var ret = JavaHelper.callMethod(this, arguments); // HashMap.put.call(this, arguments)
        JavaHelper.printStack();
        JavaHelper.printArguments(arguments, ret);
        return ret;
    }
});
```

在终端中运行
```bash
$ at-frida -l android.js
```

**2) 当然也可以使用python方式调用**

如android.py文件：
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from linktools.frida import FridaApplication
from linktools.frida.server import FridaAndroidServer


jscode = """
Java.perform(function () {
    JavaHelper.hookMethods(
        "java.util.HashMap", "put", JavaHelper.getHookImpl({printStack: false, printArgs: true})
    );
});
"""

if __name__ == "__main__":

    with FridaAndroidServer() as server:

        app = FridaApplication(
            server,
            eval_code=jscode,
            enable_spawn_gating=True
        )

        for target_app in app.enumerate_applications():
            if target_app.identifier == "com.topjohnwu.magisk":
                app.load_script(target_app.pid)

        app.run()
```

在终端中运行
```bash
$ python3 android.py
```

**3) 输出效果**

![frida](https://raw.githubusercontent.com/ice-black-tea/Zelda/master/link/images/frida.png)

**4) 内置js使用方式**

内置JavaHelper类的成员函数

```javascript
/**
 * 获取java类的类对象
 * :param className:    java类名
 * :param classloader:  java类所在的classLoader，若不填则遍历所有classloader
 * :return:             类对象
 */
function findClass(className, classloader) {}

/**
 * hook指定方法对象
 * :param clazz:        java类名/类对象
 * :param method:       java方法名/方法对象
 * :param signatures:   java方法签名，为null表示不设置签名
 * :param impl:         hook实现，如调用原函数： function(obj, args) { return this(obj, args); }
 */
function hookMethod(clazz, method, signatures, impl) {}

/**
 * hook指定方法名的所有重载
 * :param clazz:        java类名/类对象
 * :param method:       java方法名
 * :param impl:         hook实现，如调用原函数： function(obj, args) { return this(obj, args); }
 */
function hookMethods(clazz, methodName, impl) {}

/**
 * hook指定类的所有构造方法
 * @param clazz java类名/类对象
 * @param impl hook实现，如调用原函数： function(obj, args) { return this(obj, args); }
 */
function hookAllConstructors(clazz, impl) {}

/**
 * hook指定类的所有成员方法
 * @param clazz java类名/类对象
 * @param impl hook实现，如调用原函数： function(obj, args) { return this(obj, args); }
 */
function hookAllMethods(clazz, impl) {}

/**
 * hook指定类的所有方法
 * :param clazz:        java类名/类对象
 * :param impl:         hook实现，如调用原函数： function(obj, args) { return this(obj, args); }
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
 * 获取hook实现，调用原方法并展示栈和返回值
 * :param options:      hook选项，如：{stack: true, args: true, thread: true}
 * :return:             hook实现
 */
function getEventImpl(options) {}

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
 * 打印当前参数和返回值
 * :param args:         参数
 * :param ret:          返回值
 */
function printArguments(args, ret) {}
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

#### 2.2.7 at-agent

测试android-tools.apk时使用
