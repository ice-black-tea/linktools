package org.ironman.framework.proxy;

import android.os.Build;

import org.ironman.framework.util.LogUtil;
import org.ironman.framework.util.ReflectHelper;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

public class ActivityManagerProxy extends AbstractProxy implements InvocationHandler {

    private static final String TAG = ActivityManagerProxy.class.getSimpleName();

    private Object mActivityManager = null;
    private Object mActivityManagerSingleton = null;

    @Override
    protected void internalInit() throws Exception {
        ReflectHelper helper = ReflectHelper.getDefault();

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            mActivityManagerSingleton = helper.get(
                    "android.app.ActivityManager",
                    "IActivityManagerSingleton"
            );
            mActivityManager = helper.invoke(
                    mActivityManagerSingleton,
                    "get"
            );
        } else {
            mActivityManagerSingleton = helper.get(
                    "android.app.ActivityManagerNative",
                    "gDefault"
            );
            mActivityManager = helper.invoke(
                    mActivityManagerSingleton,
                    "get"
            );
        }
    }

    @Override
    protected void internalHook() throws Exception {
        if (mActivityManagerSingleton != null && mActivityManager != null) {
            Object proxy = Proxy.newProxyInstance(
                    mActivityManager.getClass().getClassLoader(),
                    mActivityManager.getClass().getInterfaces(),
                    this);
            ReflectHelper.getDefault().set(
                    mActivityManagerSingleton,
                    "mInstance",
                    proxy);
        }
    }

    @Override
    protected void internalUnhook() throws Exception {
        if (mActivityManagerSingleton != null && mActivityManager != null) {
            ReflectHelper.getDefault().set(
                    mActivityManagerSingleton,
                    "mInstance",
                    mActivityManager);
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
        return method.invoke(mActivityManager, objects);
    }
}
