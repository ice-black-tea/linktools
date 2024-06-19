# Linktools Toolkit

## 开始使用

### 依赖项

python & pip (3.6及以上): <https://www.python.org/downloads/>

### 安装

使用pip安装linktools

```bash
# pip直接安装linktools，按需添加依赖项，推荐使用all添加所有依赖项
python3 -m pip install -U "linktools[all]"
# 也可以用以下命令安装github上的最新版本:
# python3 -m pip install --ignore-installed "linktools@ git+https://github.com/ice-black-tea/linktools.git@master"
```

额外的依赖项以及相应功能可通过[requirements.yml](https://github.com/ice-black-tea/linktools/blob/master/requirements.yml)查看

### 配置alias（推荐）

对于*nix等系统，推荐在~/.bashrc 或 ~/.bash_profile 或 ~/.zshrc等文件中配置，简化调用方式，如：

```bash
# 对于未正确设置PATH环境变量，或者使用venv安装模块，会出现命令找不到的情况（command not found: lt）
# 可通过以下命令生成alias脚本添加相关命令
# 需要注意此处python3需要替换成自己安装环境下的interpreter，比如~/projects/linktools/venv/bin/python
eval "$(python3 -m linktools.cli.commands.common.env --silent alias --shell bash)"

# 给命令添加自动补全功能
eval "$(ct-env --silent completion --shell bash)"  

# 配置全局java环境，指定java版本号（如：11.0.23/17.0.11/22.0.1）
eval "$(ct-env --silent java 17.0.11 --shell bash)"

# alias简化调用
alias adb="at-adb"
alias pidcat="at-pidcat"
alias sib="it-sib"

# alias简化各类工具调用
alias apktool="ct-tools apktool"
alias burpsuite="ct-tools burpsuite"
alias jadx="ct-tools --set version=1.5.0 jadx-gui"  # 指定jadx版本号
```

## 相关功能

```
$ python3 -m linktools
    ___       __   __              __
   / (_)___  / /__/ /_____  ____  / /____
  / / / __ \/ //_/ __/ __ \/ __ \/ / ___/  linktools toolkit (v0.0.1.dev0)
 / / / / / / ,< / /_/ /_/ / /_/ / (__  )   by: Hu Ji <669898595@qq.com>
/_/_/_/ /_/_/|_|\__/\____/\____/_/____/

📎 All commands
├── 📖 at: Android scripts
│   ├── 👉 adb: Adb supports managing multiple android devices
│   ├── 👉 agent: Debug android-tools.apk
│   ├── 👉 app: Fetch application info
│   ├── 👉 debug: Debug app by jdb
│   ├── 👉 frida: Easy to use frida (require Android device rooted)
│   ├── 👉 info: Fetch device information
│   ├── 📘 intent: Common intent actions
│   ├── 👉 objection: Easy to use objection (require Android device rooted)
│   ├── 👉 pidcat: Filter logcat by package name
│   └── 👉 top: Fetch current running app's basic information
├── 📖 ct: Common scripts
│   ├── 👉 cert: Display X.509 certificate information
│   ├── 📘 cntr: Deploy docker/pod containers
│   ├── 📘 env: Linktools environment commands
│   ├── 👉 grep: Match files with regular expression
│   └── 👉 tools: Download and use tools
└── 📖 it: iOS scripts
    ├── 👉 frida: Easy to use frida (require iOS device jailbreak)
    ├── 👉 ipa: Parse ipa file
    ├── 👉 objection: Easy to use objection (require iOS device jailbreak)
    ├── 👉 scp: OpenSSH secure file copy (require iOS device jailbreak)
    ├── 👉 sib: Sib supports managing multiple ios devices
    └── 👉 ssh: OpenSSH remote login client (require iOS device jailbreak)
```

### 通用功能（脚本前缀为ct-）

#### 👉 ct-env

<details>
<summary>环境配置相关命令</summary>

##### 常用命令

```bash
# 生成alias脚本，常配合~/.bashrc等文件使用
$ ct-env --silent alias --shell bash

# 生成自动补全脚本，常配合~/.bashrc等文件使用
$ ct-env --silent completion --shell bash

# 生成配置java环境变量脚本，常配合~/.bashrc等文件使用
$ ct-env --silent java 17.0.11 --shell bash

# 进入已初始化相关环境变量的shell
$ ct-env shell

# 清除项目中7天以上未使用的缓存文件
$ ct-env clean 7
```

</details>

#### 👉 ct-grep

<details>
<summary>类似linux中的grep，正则匹配文件内容 ，额外添加解析zip、elf等格等功能</summary>

![ct-grep](https://raw.githubusercontent.com/ice-black-tea/linktools/master/images/ct-grep.png)

</details>

#### 👉 ct-tools

<details>
<summary>读取配置文件，即可下载使用对应工具，声明了adb、jadx、apktool、baksmali等常用工具</summary>

##### 常用命令

所有声明的工具可通过[配置文件](https://github.com/ice-black-tea/linktools/blob/master/src/linktools/template/tools.yml)查看，此处以apktool举例

```bash
# 初始化并执行apktool命令
$ ct-tools apktool -h

# 查看apktool相关配置
$ ct-tools --config apktool

# 只初始化不执行
$ ct-tools --download apktool

# 清除apktool相关文件
$ ct-tools --clear apktool

# 后台运行apktool
$ ct-tools --daemon apktool

# 修改apktool版本号
$ ct-tools --set version=2.5.0 apktool
```

</details>

#### 👉 ct-cntr

<details>
<summary>docker/pod容器一键部署工具，集成了包括nginx、nextcloud、redorid等等容器</summary>

##### 参考

1. [搭建homelab](https://github.com/ice-black-tea/cntr-homelab)
2. [搭建redroid](https://github.com/redroid-rockchip)

</details>

### android相关功能（脚本前缀为at-）

#### 👉 at-adb

<details>
<summary>若环境变量中存在adb，则直接执行，否则自动下载最新版本。该功能支持操作多台手机</summary>

```
$ at-adb -h
usage: at-adb [-h] [--version] [--verbose] [--debug] [--time | --no-time] [--level | --no-level] [-s SERIAL | -d | -e | -c IP[:PORT] | -l] ...

Adb that supports multiple devices

    ___       __   __              __
   / (_)___  / /__/ /_____  ____  / /____
  / / / __ \/ //_/ __/ __ \/ __ \/ / ___/  linktools toolkit (v0.0.1.dev0)
 / / / / / / ,< / /_/ /_/ / /_/ / (__  )   by: Hu Ji <669898595@qq.com>
/_/_/_/ /_/_/|_|\__/\____/\____/_/____/

positional arguments:
  adb_args              adb args

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit

log arguments:
  --verbose             increase log verbosity
  --debug               enable debug mode and increase log verbosity
  --time, --no-time     show log time
  --level, --no-level   show log level

adb arguments:
  -s SERIAL, --serial SERIAL
                        use device with given serial (adb -s option)
  -d, --device          use USB device (adb -d option)
  -e, --emulator        use TCP/IP device (adb -e option)
  -c IP[:PORT], --connect IP[:PORT]
                        use device with TCP/IP
  -l, --last            use last device
```

</details>

#### 👉 at-pidcat

<details>
<summary>集成了pidcat，并且修复了中文字符宽度问题，原项目链接：https://github.com/JakeWharton/pidcat</summary>

```
$ at-pidcat -h                                                                                                                                      ░▒▓ ✔  12:34:18
usage: at-pidcat [-h] [--verbose] [--debug] [--time | --no-time] [--level | --no-level] [-s SERIAL | -d | -e | --connect IP[:PORT] | --last] [-w N]
                 [-l {V,D,I,W,E,F,v,d,i,w,e,f}] [--color-gc] [--always-display-tags] [--top] [-c] [-t TAG] [-i IGNORED_TAG] [-v] [-a]
                 [package ...]

Filter logcat by package name

    ___       __   __              __
   / (_)___  / /__/ /_____  ____  / /____
  / / / __ \/ //_/ __/ __ \/ __ \/ / ___/  linktools toolkit (v0.0.1.dev0)
 / / / / / / ,< / /_/ /_/ / /_/ / (__  )   by: Hu Ji <669898595@qq.com>
/_/_/_/ /_/_/|_|\__/\____/\____/_/____/

positional arguments:
  package               application package name(s)

options:
  -h, --help            show this help message and exit
  -w N, --tag-width N   width of log tag
  -l {V,D,I,W,E,F,v,d,i,w,e,f}, --min-level {V,D,I,W,E,F,v,d,i,w,e,f}
                        minimum level to be displayed
  --color-gc            color garbage collection
  --always-display-tags
                        always display the tag name
  --top, --current      filter logcat by current running app
  -c, --clear           clear the entire log before running
  -t TAG, --tag TAG     filter output by specified tag(s)
  -i IGNORED_TAG, --ignore-tag IGNORED_TAG
                        filter output by ignoring specified tag(s)
  -v, --version         print the version number and exit
  -a, --all             print all log messages

log arguments:
  --verbose             increase log verbosity
  --debug               enable debug mode and increase log verbosity
  --time, --no-time     show log time
  --level, --no-level   show log level

adb arguments:
  -s SERIAL, --serial SERIAL
                        use device with given serial (adb -s option)
  -d, --device          use USB device (adb -d option)
  -e, --emulator        use TCP/IP device (adb -e option)
  --connect IP[:PORT]   use device with TCP/IP
  --last                use last device
```

</details>

#### 👉 at-top

<details>
<summary>显示顶层应用信息、获取顶层应用apk、截屏等</summary>

```
$ at-top -h                                                                                                                                         ░▒▓ ✔  12:35:00
usage: at-top [-h] [--version] [--verbose] [--debug] [--time | --no-time] [--level | --no-level] [-s SERIAL | -d | -e | -c IP[:PORT] | -l]
              [-p | -a | --path | --kill | --apk [DEST] | --screen [DEST]]

Fetch current running app's basic information

    ___       __   __              __
   / (_)___  / /__/ /_____  ____  / /____
  / / / __ \/ //_/ __/ __ \/ __ \/ / ___/  linktools toolkit (v0.0.1.dev0)
 / / / / / / ,< / /_/ /_/ / /_/ / (__  )   by: Hu Ji <669898595@qq.com>
/_/_/_/ /_/_/|_|\__/\____/\____/_/____/

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -p, --package         show current package name
  -a, --activity        show current activity name
  --path                show current apk path
  --kill                kill current package
  --apk [DEST]          pull current apk file
  --screen [DEST]       capture screen and pull file

log arguments:
  --verbose             increase log verbosity
  --debug               enable debug mode and increase log verbosity
  --time, --no-time     show log time
  --level, --no-level   show log level

adb arguments:
  -s SERIAL, --serial SERIAL
                        use device with given serial (adb -s option)
  -d, --device          use USB device (adb -d option)
  -e, --emulator        use TCP/IP device (adb -e option)
  -c IP[:PORT], --connect IP[:PORT]
                        use device with TCP/IP
  -l, --last            use last device
```

</details>

#### 👉 at-app

<details>
<summary>通过执行agent调用pms读取app基本信息并展示，组件、权限等信息相对静态检测更为准确</summary>

```
$ at-app -h                                                                                                                                         ░▒▓ ✔  12:36:09
usage: at-app [-h] [--version] [--verbose] [--debug] [--time | --no-time] [--level | --no-level] [-s SERIAL | -d | -e | -c IP[:PORT] | -l] [-t | -a | -p pkg [pkg ...] |
              -u uid [uid ...] | --system | --non-system] [--simple] [--dangerous] [-o field [field ...]]

Fetch application info

    ___       __   __              __
   / (_)___  / /__/ /_____  ____  / /____
  / / / __ \/ //_/ __/ __ \/ __ \/ / ___/  linktools toolkit (v0.0.1.dev0)
 / / / / / / ,< / /_/ /_/ / /_/ / (__  )   by: Hu Ji <669898595@qq.com>
/_/_/_/ /_/_/|_|\__/\____/\____/_/____/

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -t, --top             fetch current running app only
  -a, --all             fetch all apps
  -p pkg [pkg ...], --packages pkg [pkg ...]
                        fetch target apps only
  -u uid [uid ...], --uids uid [uid ...]
                        fetch apps with specified uids only
  --system              fetch system apps only
  --non-system          fetch non-system apps only
  --simple              display simple info only
  --dangerous           display dangerous permissions and components only
  -o field [field ...], --order-by field [field ...]
                        order by target field

log arguments:
  --verbose             increase log verbosity
  --debug               enable debug mode and increase log verbosity
  --time, --no-time     show log time
  --level, --no-level   show log level

adb arguments:
  -s SERIAL, --serial SERIAL
                        use device with given serial (adb -s option)
  -d, --device          use USB device (adb -d option)
  -e, --emulator        use TCP/IP device (adb -e option)
  -c IP[:PORT], --connect IP[:PORT]
                        use device with TCP/IP
  -l, --last            use last device
```

**输出效果**

![at-app](https://raw.githubusercontent.com/ice-black-tea/linktools/master/images/at-app.png)

</details>

#### 👉 at-inetnt

<details>
<summary>打包了常用intent操作，支持如打开设置界面、开发者选项界面、app设置界面、安装证书、打开浏览器链接等功能</summary>

##### 常用命令

```bash
# 跳转到设置页
$ at-intent setting

# 跳转到开发者选项页
$ at-intent setting-dev

# 跳转到app设置页
$ at-intent setting-app

# 安装证书
$ at-intent setting-cert ~/test.crt

# 安装apk
$ at-intent install https://example.com/test.apk

# 浏览器中打开特定页，也可用于测试url scheme
$ at-intent browser https://example.com
```

</details>

#### 👉 at-frida

<details>
<summary>该功能旨在方便使用frida，可自动下载server，支持加载远程脚本，并内置了常用功能</summary>

##### 相关特性
1. 可以支持根据android设备和python的frida版本，全自动完成下载、推送、运行frida server
2. 监听了spawn进程变化情况，可以同时hook主进程和各个子进程
3. 监听js文件变化，实时加载
4. 注入了内置脚本，封装常用功能，如：过ssl pinning
5. 支持加载远程脚本
6. 支持重定向设备流量到本地端口

##### 使用方式

**1) 以命令行方式运行**

```bash
# 从本地加载~/test/frida.js脚本，以spawn模式注入到me.ele进程中
$ at-frida -l ~/test/frida.js -p me.ele --spawn

# 从远程加载frida脚本，注入到me.ele进程中，并将me.ele流量重定向到本地8080端口
$ at-frida -c https://raw.githubusercontent.com/ice-black-tea/linktools/master/agents/frida/test/android.js -p me.ele --redirect-port 8080

# 只启动frida-server，不注入脚本
$ at-frida --serve --remote-port 27042 --local-port 27042 -p fake_package

# 不启动frida-server，通过设备上frida server启动的27042端口，注入到me.ele进程中
$ at-frida --no-serve --remote-port 27042 -p me.ele
```

**2) 使用python方式调用**

执行如下python脚本即可自动开启frida-server，并将js代码注入到指定进程，参考[src/linktools/cli/commands/android/frida.py](https://github.com/ice-black-tea/linktools/blob/master/src/linktools/cli/commands/android/frida.py) 

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from linktools.cli import BaseCommand
from linktools.frida import FridaApplication, FridaEvalCode
from linktools.frida.android import AndroidFridaServer

class Command(BaseCommand):

    def init_arguments(self, parser):
        pass
    
    def run(self, args):
        code = """
            Java.perform(function () {
                JavaHelper.hookMethods(
                    "java.util.HashMap",
                     "put",
                     {stack: false, args: true}
                );
            });
            """
        
        with AndroidFridaServer() as server:
            app = FridaApplication(
                server,
                user_scripts=(FridaEvalCode(code),),
                enable_spawn_gating=True,
                target_identifiers=rf"^com.topjohnwu.magisk($|:)"
            )
            app.inject_all(resume=True)
            app.run()


command = Command()
if __name__ == "__main__":
    command.main()
```

##### 内置接口

e.g. [hook接口](https://github.com/ice-black-tea/linktools/blob/master/agents/frida/lib/java.ts)

```javascript
Java.perform(function () {

    // hook特定类的指定方法
    JavaHelper.hookMethod(
        "me.ele.privacycheck.f",                    // 可以是类名，也可以是类对象 => Java.use("me.ele.privacycheck.f")
        "a",                                        // 方法名
        ['android.app.Application', 'boolean'],     // 参数类型
        function (obj, args) {                      // hook方法实现
            args[1] = true;
            return this(obj, args);                 // this代表当前hook方法，obj代表当前hook对象，args代表当前hook方法参数
        }
    );

    // hook特定类的所有名为isHttpType的方法
    JavaHelper.hookMethods(
        "anet.channel.entity.ConnType",             // 可以是类名，也可以是类对象
        "isHttpType",                               // 方法名
        () => true                                  // hook实现
    );
    
    // hook特定类的所有方法
    JavaHelper.hookAllMethods(
        "p.r.o.x.y.PrivacyApi",                     // 可以是类名，也可以是类对象
        JavaHelper.getEventImpl({                   // 生成一个通用的hook方法
            stack: true,                            // 打印堆栈
            args: true,                             // 打印参数返回值
            thread: false,
            customKey1: "自定义参数",                 // 自定义参数，会回显日志中
        })
    );
});
```

e.g. [扩展接口](https://github.com/ice-black-tea/linktools/blob/master/agents/frida/lib/android.ts)

```javascript
// 禁用ssl pinning
AndroidHelper.bypassSslPinning();

// 开启webview调试模式
AndroidHelper.setWebviewDebuggingEnabled();

// 类似Java.use()
// 如果当前classloader不存在需要找的类，则会持续监控动态加载的classloader，直到找到指定类为止
AndroidHelper.javaUse("p.r.o.x.y.PrivacyApi", function(clazz) {
    // 终于等到class出现，干点想干的事吧
});
```

</details>

#### 👉 at-agent

<details>
<summary>测试android-tools.apk时使用</summary>

```
$ at-agent -h
usage: at-agent [-h] [--version] [--verbose] [--debug] [--time | --no-time] [--level | --no-level] [-s SERIAL | -d | -e | -c IP[:PORT] | -l] [-p] ...

Debug android-tools.apk

    ___       __   __              __
   / (_)___  / /__/ /_____  ____  / /____
  / / / __ \/ //_/ __/ __ \/ __ \/ / ___/  linktools toolkit (v0.0.1.dev0)
 / / / / / / ,< / /_/ /_/ / /_/ / (__  )   by: Hu Ji <669898595@qq.com>
/_/_/_/ /_/_/|_|\__/\____/\____/_/____/

positional arguments:
  agent_args            agent args

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -p, --privilege       run with root privilege

log arguments:
  --verbose             increase log verbosity
  --debug               enable debug mode and increase log verbosity
  --time, --no-time     show log time
  --level, --no-level   show log level

adb arguments:
  -s SERIAL, --serial SERIAL
                        use device with given serial (adb -s option)
  -d, --device          use USB device (adb -d option)
  -e, --emulator        use TCP/IP device (adb -e option)
  -c IP[:PORT], --connect IP[:PORT]
                        use device with TCP/IP
  -l, --last            use last device
```

</details>

### ios相关功能（脚本前缀为it-）

#### 👉 it-frida

<details>
<summary>该功能旨在方便使用frida，支持加载远程脚本，内置了常用功能</summary>

```
$ it-frida -h                                                                                                                                       ░▒▓ ✔  12:37:52
usage: it-frida [-h] [--version] [--verbose] [--debug] [--time | --no-time] [--level | --no-level] [-u UDID | --connect IP:PORT | --last] [-b BUNDLE_ID] [--spawn]
                [-P KEY VALUE] [-l SCRIPT] [-e CODE] [-c URL] [-a]

Easy to use frida (require iOS device jailbreak)

    ___       __   __              __
   / (_)___  / /__/ /_____  ____  / /____
  / / / __ \/ //_/ __/ __ \/ __ \/ / ___/  linktools toolkit (v0.0.1.dev0)
 / / / / / / ,< / /_/ /_/ / /_/ / (__  )   by: Hu Ji <669898595@qq.com>
/_/_/_/ /_/_/|_|\__/\____/\____/_/____/

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -b BUNDLE_ID, --bundle-id BUNDLE_ID
                        target bundle id (default: frontmost application)
  --spawn               inject after spawn (default: false)
  -P KEY VALUE, --parameters KEY VALUE
                        user script parameters
  -l SCRIPT, --load SCRIPT
                        load user script
  -e CODE, --eval CODE  evaluate code
  -c URL, --codeshare URL
                        load share script url
  -a, --auto-start      automatically start when all processes exits

log arguments:
  --verbose             increase log verbosity
  --debug               enable debug mode and increase log verbosity
  --time, --no-time     show log time
  --level, --no-level   show log level

sib arguments:
  -u UDID, --udid UDID  specify unique device identifier
  --connect IP:PORT     use device with TCP/IP
  --last                use last device
```

</details>
