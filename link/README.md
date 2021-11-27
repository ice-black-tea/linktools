# Link Tools

## 开始使用

### 依赖项

python & pip (3.5及以上): <https://www.python.org/downloads/>

### 安装

直接安装

```bash
# 也可以直接使用github上的最新版本："linktools @ git+https://github.com/ice-black-tea/Zelda.git#egg=linktools&subdirectory=link"
python3 -m pip install "linktools[frida,magic]" # 如果用不到frida可以不加frida
```

### 配置环境变量（可选）

添加“LINKTOOLS_SETTING”环境变量，值为python文件的绝对路径，如：

```bash
LINKTOOLS_SETTING="/Users/admin/linktools/setting.cfg"
```

然后在setting.cfg中添加配置，如：

```python
# 下载的工具和其他缓存会默认存储在“~/linktools/”目录下，可通过以下配置修改
SETTING_DATA_PATH = "/Users/admin/linktools/data"
SETTING_TEMP_PATH = "/Users/admin/linktools/temp"

# 以“CALLBACK_”开头为回调函数，在配置加载完成时调用，回调类型函数入参为配置项字典
# 如：根据当前系统安装的chrome浏览器版本，修改chromedriver版本号
CALLBACK_GENERAL_TOOL_CHROMEDRIVER = lambda cfg: cfg["GENERAL_TOOL_CHROMEDRIVER"].update(version="1.1.1.1")
```

## 相关功能

### at-frida

注入js文件或js代码到指定进程，支持根据设备下载对应的frida-server，js文件实时加载，应用重启后注入等功能

```bash
$ at-frida -h
usage: at-frida.py [-h] [-v] [-s SERIAL] [-p PACKAGE] (-f FILE | -c CODE) [-r]

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
at-frida -f hook.js
```

#### 输出效果

![frida](https://raw.githubusercontent.com/ice-black-tea/Zelda/master/link/images/frida.png)

#### js使用

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

### at-top-app

显示顶层应用信息、获取顶层应用apk、截屏等

```bash
$ at-top-app -h
usage: at-top-app [-h] [-v] [-s SERIAL]
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

### at-inetnt

打开设置界面、开发者选项界面、app设置界面、安装证书、打开浏览器链接等

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
                        start application setting activity [default top-level
                        package]
  --setting-cert PATH   start cert installer activity and install cert (need
                        '/data/local/tmp' write permission)
  --browser URL         start browser activity and jump to url (need scheme,
                        such as https://antiy.cn)
```

### at-app

展示app基本信息

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
  -t, --top             fetch top-level app only
  -p pkg [pkg ...], --packages pkg [pkg ...]
                        fetch target apps
  -o field [field ...], --order-by field [field ...]
                        order by target field
```

#### 输出效果

![apps](https://raw.githubusercontent.com/ice-black-tea/Zelda/master/link/images/apps.png)

### ct-grep

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

### ct-tools

读取[配置文件](https://raw.githubusercontent.com/ice-black-tea/Zelda/master/link/linktools/configs/general_tools.py)，下载使用对应工具

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


### at-tools

测试android-tools.apk时使用
