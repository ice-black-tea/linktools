# Android Tools

## frida

### 方法1：运行frida hook脚本

如hook.py：
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from android_tools import frida_helper

jscode = """
Java.perform(function () {
    var HashMap = Java.use("java.util.HashMap");
    HashMap.put.implementation = function() {
        return CallMethod(this, arguments, true, true);
    }
});
"""

if __name__ == '__main__':
    frida_helper().run_script("xxx.xxx.xxx", jscode=jscode)
    sys.stdin.read()
```


### 方法2：使用at_frida.py

注入js文件或js代码到指定进程，支持js文件实时刷新

```bash
$ at_frida.py -h
usage: at_frida.py [-h] [-v] [-s SERIAL] -p PACKAGE (-f FILE | -c CODE)

easy to use frida

optional arguments:
  -h, --help            show this help message and exit
  -v, --version         show program's version number and exit
  -s SERIAL, --serial SERIAL
                        use device with given serial
  -p PACKAGE, --package PACKAGE
                        target package/process
  -f FILE, --file FILE  javascript file
  -c CODE, --code CODE  javascript code
```

如hook.js文件：
```javascript
Java.perform(function () {
    var HashMap = Java.use("java.util.HashMap");
    HashMap.put.implementation = function() {
        return CallMethod(this, arguments, true, true);
    }
});
```

在终端中运行
```bash
at_frida.py -p xxx.xxx.xxx -f hook.js
```

### 输出效果

```
[*] Stack: java.util.HashMap.put(Native Method)
        at java.util.HashMap.put(Native Method)
        at com.alibaba.fastjson.JSONObject.put(JSONObject.java:329)
        at com.aliyun.sls.android.sdk.a.b.a(LogGroup.java:41)
        at com.aliyun.sls.android.sdk.a.a(LOGClient.java:145)
        at com.wosai.cashbar.utils.log.d$2.run(AliyunSlsLogger.java:57)
        at java.util.concurrent.Executors$RunnableAdapter.call(Executors.java:422)
        at java.util.concurrent.FutureTask.runAndReset(FutureTask.java:279)
        at java.util.concurrent.ScheduledThreadPoolExecutor$ScheduledFutureTask.access$301(ScheduledThreadPoolExecutor.java:152)
        at java.util.concurrent.ScheduledThreadPoolExecutor$ScheduledFutureTask.run(ScheduledThreadPoolExecutor.java:266)
        at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1112)
        at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:587)
        at java.lang.Thread.run(Thread.java:818)
[*] Method: java.util.HashMap.put(Native Method)
        Arguments[0]: __topic__
        Arguments[1]: android-app
        Return: null
```

## at_top_app

```bash
$ at_top_app.py -h
usage: at_top_app.py [-h] [-v] [-s SERIAL]
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