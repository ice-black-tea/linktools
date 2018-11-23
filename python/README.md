# Android Tools

## 配置环境

```bash
$ cd android-library/python
$ python3 -m pip install -r requirements.txt -e .
```

## 使用

### 运行frida hook脚本

如：
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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
    frida_helper().run_script("com.hu.test", jscode=jscode)
```

输出效果

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
