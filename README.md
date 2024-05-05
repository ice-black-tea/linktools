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

额外的依赖项以及相应功能可通过[requirements.yml](https://raw.githubusercontent.com/ice-black-tea/linktools/master/requirements.yml)查看

### 配置alias（推荐）

对于*nix等系统，推荐在~/.bashrc 或 ~/.bash_profile 或 ~/.zshrc等文件中配置alias，简化调用方式：

```bash
eval "$(ct-env --silent completion --shell bash)" # 给命令添加自动补全功能

alias adb="at-adb"
alias pidcat="at-pidcat"
alias sib="it-sib"

alias apktool="ct-tools apktool"
alias burpsuite="ct-tools burpsuite"
alias jadx="ct-tools --set version=1.5.0 jadx-gui" # 指定jadx版本号，配置jvm最大内存
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

#### 👉 ct-cntr

<details>
<summary>docker/pod容器一键部署工具，集成了包括nginx、nextcloud、redorid等等容器</summary>

```
$ ct-cntr -h
usage: ct-cntr [-h] [--verbose] [--debug] [--time | --no-time] [--level | --no-level] [--version] COMMAND ...

Deploy docker/pod containers

    ___       __   __              __
   / (_)___  / /__/ /_____  ____  / /____
  / / / __ \/ //_/ __/ __ \/ __ \/ / ___/  linktools toolkit (v0.0.1.dev0)
 / / / / / / ,< / /_/ /_/ / /_/ / (__  )   by: Hu Ji <669898595@qq.com>
/_/_/_/ /_/_/|_|\__/\____/\____/_/____/

positional arguments:
  COMMAND              Command Help
    list               list all containers
    add                add containers to installed list
    remove             remove containers from installed list
    info               display container info
    up                 deploy installed containers
    restart            restart installed containers
    down               stop installed containers
    exec               exec container command
    config             manage container configs
    repo               manage container repository

options:
  -h, --help           show this help message and exit
  --version            show program's version number and exit

log options:
  --verbose            increase log verbosity
  --debug              increase linktools's log verbosity, and enable debug mode
  --time, --no-time    show log time
  --level, --no-level  show log level
```

</details>

#### 👉 ct-grep

<details>
<summary>类似linux中的grep，正则匹配文件内容 ，额外添加解析zip、elf等格等功能</summary>

```
$ usage: ct-grep [-h] [--version] [--verbose] [--debug] [--time | --no-time] [--level | --no-level] [-i] pattern [file ...]

Match files with regular expression

    ___       __   __              __
   / (_)___  / /__/ /_____  ____  / /____
  / / / __ \/ //_/ __/ __ \/ __ \/ / ___/  linktools toolkit (v0.0.1.dev0)
 / / / / / / ,< / /_/ /_/ / /_/ / (__  )   by: Hu Ji <669898595@qq.com>
/_/_/_/ /_/_/|_|\__/\____/\____/_/____/

positional arguments:
  pattern              regular expression
  file                 target files path

options:
  -h, --help           show this help message and exit
  --version            show program's version number and exit
  -i, --ignore-case    ignore case

log arguments:
  --verbose            increase log verbosity
  --debug              enable debug mode and increase log verbosity
  --time, --no-time    show log time
  --level, --no-level  show log level
```

</details>

#### 👉 ct-tools

<details>
<summary>读取配置文件，即可下载使用对应工具，声明了adb、jadx、apktool、baksmali等常用工具</summary>

所有声明的工具可通过[配置文件](https://raw.githubusercontent.com/ice-black-tea/linktools/master/src/linktools/template/tools.yml)查看

```
$ usage: ct-tools [-h] [--version] [--verbose] [--debug] [--time | --no-time] [--level | --no-level] [-c | --download | --clear | -d] ...

Tools downloaded from the web

    ___       __   __              __
   / (_)___  / /__/ /_____  ____  / /____
  / / / __ \/ //_/ __/ __ \/ __ \/ / ___/  linktools toolkit (v0.0.1.dev0)
 / / / / / / ,< / /_/ /_/ / /_/ / (__  )   by: Hu Ji <669898595@qq.com>
/_/_/_/ /_/_/|_|\__/\____/\____/_/____/

positional arguments:
  {aapt,adb,apksigner,apktool,appcrawler,baksmali,chromedriver,dex2jar,fastboot,ghidra,ipatool,jadx,jadx-gui,jar2dex,java,sib,smali,tidevice,uber-apk-signer,zipalign}

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -c, --config          show the config of tool
  --download            download tool files
  --clear               clear tool files
  -d, --daemon          execute tools as a daemon

log arguments:
  --verbose             increase log verbosity
  --debug               enable debug mode and increase log verbosity
  --time, --no-time     show log time
  --level, --no-level   show log level
```

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

#### 👉 at-inetnt

<details>
<summary>打包了常用intent操作，支持如打开设置界面、开发者选项界面、app设置界面、安装证书、打开浏览器链接等功能</summary>

```
$ at-intent -h                                                                                                                                      ░▒▓ ✔  12:35:32
usage: at-intent [-h] [--version] [--verbose] [--debug] [--time | --no-time] [--level | --no-level] [-s SERIAL | -d | -e | -c IP[:PORT] | -l]
                 (--setting | --setting-dev | --setting-dev2 | --setting-app [PACKAGE] | --setting-cert PATH | --install PATH | --browser URL)

Common intent actions

    ___       __   __              __
   / (_)___  / /__/ /_____  ____  / /____
  / / / __ \/ //_/ __/ __ \/ __ \/ / ___/  linktools toolkit (v0.0.1.dev0)
 / / / / / / ,< / /_/ /_/ / /_/ / (__  )   by: Hu Ji <669898595@qq.com>
/_/_/_/ /_/_/|_|\__/\____/\____/_/____/

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --setting             start setting activity
  --setting-dev         start development setting activity
  --setting-dev2        start development setting activity
  --setting-app [PACKAGE]
                        start application setting activity (default: current running package)
  --setting-cert PATH   install cert (need '/data/local/tmp' write permission)
  --install PATH        install apk file (need '/data/local/tmp' write permission)
  --browser URL         start browser activity and jump to url (need scheme, such as https://antiy.cn)

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

![apps](https://raw.githubusercontent.com/ice-black-tea/linktools/master/images/apps.png)

</details>

#### 👉 at-frida

<details>
<summary>该功能旨在方便使用frida，可自动下载server，支持加载远程脚本，并内置了常用功能</summary>

提供了以下特性：
1. 可以支持根据设备和本地安装的frida版本，自动下载并推送frida server到设备，启动frida server自动化完成
2. 监听了spawn进程变化情况，可以同时hook主进程和各个子进程
3. 监听js文件变化，实时加载
4. 注入了内置脚本，封装常用功能，如：过ssl pinning

```
$ at-frida -h                                                                                                                                       ░▒▓ ✔  12:36:48
usage: at-frida [-h] [--version] [--verbose] [--debug] [--time | --no-time] [--level | --no-level] [-s SERIAL | -d | --emulator | --connect IP[:PORT] | --last]
                [-p PACKAGE] [--spawn] [-P KEY VALUE] [-l SCRIPT] [-e CODE] [-c URL] [--redirect-address ADDRESS] [--redirect-port PORT] [-a]

Easy to use frida (require Android device rooted)

    ___       __   __              __
   / (_)___  / /__/ /_____  ____  / /____
  / / / __ \/ //_/ __/ __ \/ __ \/ / ___/  linktools toolkit (v0.0.1.dev0)
 / / / / / / ,< / /_/ /_/ / /_/ / (__  )   by: Hu Ji <669898595@qq.com>
/_/_/_/ /_/_/|_|\__/\____/\____/_/____/

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  -p PACKAGE, --package PACKAGE
                        target package (default: frontmost application)
  --spawn               inject after spawn (default: false)
  -P KEY VALUE, --parameters KEY VALUE
                        user script parameters
  -l SCRIPT, --load SCRIPT
                        load user script
  -e CODE, --eval CODE  evaluate code
  -c URL, --codeshare URL
                        load share script url
  --redirect-address ADDRESS
                        redirect traffic to target address (default: localhost)
  --redirect-port PORT  redirect traffic to target port (default: 8080)
  -a, --auto-start      automatically start when all processes exits

log arguments:
  --verbose             increase log verbosity
  --debug               enable debug mode and increase log verbosity
  --time, --no-time     show log time
  --level, --no-level   show log level

adb arguments:
  -s SERIAL, --serial SERIAL
                        use device with given serial (adb -s option)
  -d, --device          use USB device (adb -d option)
  --emulator            use TCP/IP device (adb -e option)
  --connect IP[:PORT]   use device with TCP/IP
  --last                use last device
```

**1) 以命令行方式运行**

比如要加载 [https://raw.githubusercontent.com/ice-black-tea/linktools/master/agent/frida/test/java.js](https://raw.githubusercontent.com/ice-black-tea/linktools/master/agent/frida/test/java.js) 脚本：

在终端中运行
```bash
$ at-frida -c https://raw.githubusercontent.com/ice-black-tea/linktools/master/agent/frida/test/java.js
```

输出如下：
```
[15:24:09]  I  Download ShareScript(filename=https://raw.githubusercontent.com/ice-black-tea/linktools/master/agent/frida/test/java.js)
[15:24:11]  W  java.js ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 1,704/513 bytes ? 100% eta 0:00:00
[15:24:13]  I  Load trusted ShareScript(filename=https://raw.githubusercontent.com/ice-black-tea/linktools/master/agent/frida/test/java.js)
[15:24:14]  I  Start frida server ...
[15:24:15]  I  Frida server is running ...
[15:24:18]  I  Load ScriptFile(filename=/Users/huji/Projects/linktools/src/linktools/assets/frida.min.js)
[15:24:19]  I  Session(pid=32087, name=马赛克) attached
[15:24:19]  I  Hook method: java.lang.String android.net.Uri.access$300()
[15:24:19]  I  Hook method: java.lang.String android.net.Uri.access$600()
[15:24:19]  I  Hook method: java.lang.String android.net.Uri.decode(java.lang.String)
[15:24:19]  I  Hook method: java.lang.String android.net.Uri.encode(java.lang.String)
[15:24:19]  I  Hook method: java.lang.String android.net.Uri.encode(java.lang.String, java.lang.String)
[15:24:19]  I  Hook method: android.net.Uri android.net.Uri.fromFile(java.io.File)
[15:24:19]  I  Hook method: android.net.Uri android.net.Uri.fromParts(java.lang.String, java.lang.String, java.lang.String)
[15:24:19]  I  Hook method: boolean android.net.Uri.isAllowed(char, java.lang.String)
[15:24:19]  I  Hook method: android.net.Uri android.net.Uri.parse(java.lang.String)
[15:24:19]  I  Hook method: android.net.Uri android.net.Uri.withAppendedPath(android.net.Uri, java.lang.String)
[15:24:19]  I  Hook method: void android.net.Uri.writeToParcel(android.os.Parcel, android.net.Uri)
[15:24:19]  I  Hook method: android.net.Uri$Builder android.net.Uri.buildUpon()
[15:24:19]  I  Hook method: void android.net.Uri.checkContentUriWithoutPermission(java.lang.String, int)
[15:24:19]  I  Hook method: void android.net.Uri.checkFileUriExposed(java.lang.String)
[15:24:19]  I  Hook method: int android.net.Uri.compareTo(android.net.Uri)
[15:24:19]  I  Hook method: int android.net.Uri.compareTo(java.lang.Object)
[15:24:19]  I  Hook method: boolean android.net.Uri.equals(java.lang.Object)
[15:24:19]  I  Hook method: java.lang.String android.net.Uri.getAuthority()
[15:24:19]  I  Hook method: boolean android.net.Uri.getBooleanQueryParameter(java.lang.String, boolean)
[15:24:19]  I  Hook method: android.net.Uri android.net.Uri.getCanonicalUri()
[15:24:19]  I  Hook method: java.lang.String android.net.Uri.getEncodedAuthority()
[15:24:19]  I  Hook method: java.lang.String android.net.Uri.getEncodedFragment()
[15:24:19]  I  Hook method: java.lang.String android.net.Uri.getEncodedPath()
[15:24:19]  I  Hook method: java.lang.String android.net.Uri.getEncodedQuery()
[15:24:19]  I  Hook method: java.lang.String android.net.Uri.getEncodedSchemeSpecificPart()
[15:24:19]  I  Hook method: java.lang.String android.net.Uri.getEncodedUserInfo()
[15:24:19]  I  Hook method: java.lang.String android.net.Uri.getFragment()
[15:24:19]  I  Hook method: java.lang.String android.net.Uri.getHost()
[15:24:19]  I  Hook method: java.lang.String android.net.Uri.getLastPathSegment()
[15:24:19]  I  Hook method: java.lang.String android.net.Uri.getPath()
[15:24:19]  I  Hook method: java.util.List android.net.Uri.getPathSegments()
[15:24:19]  I  Hook method: int android.net.Uri.getPort()
[15:24:19]  I  Hook method: java.lang.String android.net.Uri.getQuery()
[15:24:19]  I  Hook method: java.lang.String android.net.Uri.getQueryParameter(java.lang.String)
[15:24:19]  I  Hook method: java.util.Set android.net.Uri.getQueryParameterNames()
[15:24:19]  I  Hook method: java.util.List android.net.Uri.getQueryParameters(java.lang.String)
[15:24:19]  I  Hook method: java.lang.String android.net.Uri.getScheme()
[15:24:19]  I  Hook method: java.lang.String android.net.Uri.getSchemeSpecificPart()
[15:24:19]  I  Hook method: java.lang.String android.net.Uri.getUserInfo()
[15:24:19]  I  Hook method: int android.net.Uri.hashCode()
[15:24:19]  I  Hook method: boolean android.net.Uri.isAbsolute()
[15:24:19]  I  Hook method: boolean android.net.Uri.isHierarchical()
[15:24:19]  I  Hook method: boolean android.net.Uri.isOpaque()
[15:24:19]  I  Hook method: boolean android.net.Uri.isPathPrefixMatch(android.net.Uri)
[15:24:19]  I  Hook method: boolean android.net.Uri.isRelative()
[15:24:19]  I  Hook method: android.net.Uri android.net.Uri.normalizeScheme()
[15:24:19]  I  Hook method: java.lang.String android.net.Uri.toSafeString()
[15:24:19]  I  Hook method: java.lang.String android.net.Uri.toString()
[15:24:27]  I  Script(pid=32087, name=马赛克) event count=1 in the Group(pid, method):
               {
                 "event_type": "测试",
                 "event_args": "测试参数",
                 "class_name": "android.net.Uri",
                 "method_name": "void android.net.Uri.writeToParcel(android.os.Parcel, android.net.Uri)",
                 "method_simple_name": "writeToParcel",
                 "args": [
                   "android.os.Parcel@b660fca",
                   null
                 ],
                 "error": null,
                 "stack": [
                   "android.net.Uri.writeToParcel(Native Method)",
                   "android.content.Intent.writeToParcel(Intent.java:10840)",
                   "android.app.IActivityManager$Stub$Proxy.bindIsolatedService(IActivityManager.java:6210)",
                   "android.app.ContextImpl.bindServiceCommon(ContextImpl.java:1843)",
                   "android.app.ContextImpl.bindService(ContextImpl.java:1759)",
                   "android.content.ContextWrapper.bindService(ContextWrapper.java:767)",
                   "马赛克.RemoteGetterHelper.asyncBindService(SourceFile:124)",
                   "马赛克.RemoteGetterHelper.initRemoteGetterAndWait(SourceFile:70)",
                   "马赛克.NetworkProxy.initDelegateInstance(SourceFile:99)",
                   "马赛克.NetworkProxy.getConnection(SourceFile:51)",
                   "马赛克.ANetwork.<init>(SourceFile:50)",
                   "马赛克.DownloadTask.run(SourceFile:130)",
                   "java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1167)",
                   "java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:641)",
                   "java.lang.Thread.run(Thread.java:923)"
                 ]
[15:24:27]  I  Script(pid=32087, name=马赛克) event count=2 in the Group(pid, method):
               {
                 "event_type": "测试",
                 "event_args": "测试参数",
                 "class_name": "android.net.Uri",
                 "method_name": "void android.net.Uri.writeToParcel(android.os.Parcel, android.net.Uri)",
                 "method_simple_name": "writeToParcel",
                 "args": [
                   "android.os.Parcel@36941ab",
                   null
                 ],
                 "error": null,
                 "stack": [
                   "android.net.Uri.writeToParcel(Native Method)",
                   "android.content.Intent.writeToParcel(Intent.java:10840)",
                   "android.app.IActivityManager$Stub$Proxy.bindIsolatedService(IActivityManager.java:6210)",
                   "android.app.ContextImpl.bindServiceCommon(ContextImpl.java:1843)",
                   "android.app.ContextImpl.bindService(ContextImpl.java:1759)",
                   "android.content.ContextWrapper.bindService(ContextWrapper.java:767)",
                   "马赛克.bindRemoteService(SourceFile:737)",
                   "马赛克.asyncGetRemoteService(SourceFile:642)",
                   "马赛克$2.run(SourceFile:112)",
                   "java.util.concurrent.Executors$RunnableAdapter.call(Executors.java:462)",
                   "java.util.concurrent.FutureTask.run(FutureTask.java:266)",
                   "java.util.concurrent.ScheduledThreadPoolExecutor$ScheduledFutureTask.run(ScheduledThreadPoolExecutor.java:301)",
                   "java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1167)",
                   "java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:641)",
                   "java.lang.Thread.run(Thread.java:923)"
                 ]
               }
```

**2) 当然也可以使用python方式调用**

执行如下python脚本即可自动开启frida-server，并将js代码注入到指定进程中，若需要同时注入子进程，按[src/linktools/cli/scripts/android/frida.py](https://raw.githubusercontent.com/ice-black-tea/linktools/master/src/linktools/cli/scripts/android/frida.py) 重写 FridaApplication 的 on_spawn_added 方法即可

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging
from linktools.frida import FridaApplication, FridaEvalCode
from linktools.frida.android import AndroidFridaServer

jscode = """
Java.perform(function () {
    JavaHelper.hookMethods(
        "java.util.HashMap", "put", {stack: false, args: true}
    );
});
"""

if __name__ == "__main__":

    logging.basicConfig(level=logging.INFO)

    with AndroidFridaServer() as server:

        app = FridaApplication(
            server,
            user_scripts=(FridaEvalCode(jscode),),
            enable_spawn_gating=True
        )

        for target_app in app.device.enumerate_applications():
            if target_app.pid > 0 and target_app.identifier == "com.topjohnwu.magisk":
                app.load_script(target_app.pid)

        app.run()
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
