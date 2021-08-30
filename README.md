# Zelda

## 目录结构

```tree
.
├── bow                 android项目，编译的apk产物是Link的依赖项
├── link                python项目，工具集入口
└── misc                杂项，存储一些定制脚本
```

## 使用

### 依赖项

python & pip (3.5及以上): <https://www.python.org/downloads/>

### 安装

直接安装

```bash
# 安装python模块（必须使用python3.5或以上）
# linktools @ git+https://github.com/ice-black-tea/Zelda.git#egg=linktools&subdirectory=link
python3 -m pip install "git+https://github.com/ice-black-tea/Zelda.git#egg=linktools&subdirectory=link"
```

### 卸载

```bash
# 卸载linktools模块
python3 -m pip uninstall linktools
```

### 工具集

[点这里](Link/README.md)

## todo

* frida.js添加hook重载、子类、多classloader支持、过ssl pinning...
* 添加intent fuzz功能
* 添加系统服务fuzz功能
* 添加获取所有权限（dangerous、normal、与声明保护等级不一样的权限...）
* 解决gadbd在高版本无法调用am、pm等命令功能
* 解析android端口、进程等内容，列出潜在危险点
... ...
