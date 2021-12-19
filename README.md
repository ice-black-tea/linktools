# Zelda

## 目录结构

```tree
.
├── link                工具集入口，其他文件夹都是为此服务的
├── bow                 android项目，编译的apk产物是link中android相关功能的依赖项
├── spear               frida相关脚本，编译后产物是link中frida内置脚本
└── shield              杂项，存储一些定制脚本
```

## 工具集入口

工具集入口在link目录中，详情参见：[传送门](link/README.md)

## TODO

- [ ] frida.js添加hook重载、子类、多classloader支持、过ssl pinning ... ...
- [ ] 添加intent fuzz功能
- [ ] 添加系统服务fuzz功能
- [ ] 添加获取所有权限（dangerous、normal、与声明保护等级不一样的权限...）
- [ ] 解决gadbd在高版本无法调用am、pm等命令功能
- [ ] 解析android端口、进程等内容，列出潜在危险点 ... ...
