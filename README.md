# Zelda

## 使用

### 依赖项

python & pip (3.5及以上): <https://www.python.org/downloads/>

### 安装

```bash
# 下载
git clone https://github.com/ice-black-tea/Zelda.git --depth=1
# 安装python模块（必须使用python3.5或以上）并配置环境变量（重启终端后生效）
sudo python3 Zelda/Link/install.py
```

### 卸载

```bash
# 重启终端后生效
sudo python3 Zelda/Link/install.py -u
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
