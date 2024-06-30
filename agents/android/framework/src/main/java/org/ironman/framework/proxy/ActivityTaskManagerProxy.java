package org.ironman.framework.proxy;

import android.os.Build;

import org.ironman.framework.util.LogUtil;
import org.ironman.framework.util.ReflectHelper;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

public class ActivityTaskManagerProxy extends AbstractProxy implements InvocationHandler {

    private static final String TAG = ActivityManagerProxy.class.getSimpleName();

    private Object mActivityTaskManagerSingleton = null;
    private Object mActivityTaskManager = null;

    @Override
    protected void internalInit() throws Exception {
        ReflectHelper helper = ReflectHelper.getDefault();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            // "android/app/ActivityTaskManager.java"
            mActivityTaskManagerSingleton = helper.get(
                    "android.app.ActivityTaskManager",
                    "IActivityTaskManagerSingleton"
            );
            mActivityTaskManager = helper.invoke(
                    mActivityTaskManagerSingleton,
                    "get"
            );
        }
    }

    @Override
    protected void internalHook() throws Exception {
        if (mActivityTaskManagerSingleton != null && mActivityTaskManager != null) {
            Object proxy = Proxy.newProxyInstance(
                    mActivityTaskManager.getClass().getClassLoader(),
                    mActivityTaskManager.getClass().getInterfaces(),
                    this);
            ReflectHelper.getDefault().set(
                    mActivityTaskManagerSingleton,
                    "mInstance",
                    proxy);
        }
    }

    @Override
    protected void internalUnhook() throws Exception {
        if (mActivityTaskManagerSingleton != null && mActivityTaskManager != null) {
            ReflectHelper.getDefault().set(
                    mActivityTaskManagerSingleton,
                    "mInstance",
                    mActivityTaskManager);
        }
    }

    @Override
    public Object invoke(Object o, Method method, Object[] objects) throws Throwable {
        switch (method.getName()) {
            case "startActivity":
            case "startService":
            case "broadcastIntent":
                LogUtil.d(TAG, "%s: set applicationThread null", method.getName());
                objects[0] = null; // applicationThread = null;
                break;
        }
        return method.invoke(mActivityTaskManager, objects);
    }
}
