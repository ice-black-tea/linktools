package org.ironman.framework.proxy;

import android.os.Build;

import org.ironman.framework.util.LogUtil;
import org.ironman.framework.util.ReflectUtil;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

public class ActivityManagerProxy implements InvocationHandler {

    private static final String TAG = ActivityManagerProxy.class.getSimpleName();

    private boolean mReplaced = false;
    private Object mActivityManager = null;
    private Object mActivityManagerSingleton = null;

    public ActivityManagerProxy() {
        // android.app.ActivityManagerNative.gDefault
        String targetClass = "android.app.ActivityManagerNative";
        String targetField = "gDefault";

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            // android.app.ActivityManager.IActivityManagerSingleton
            targetClass = "android.app.ActivityManager";
            targetField = "IActivityManagerSingleton";
        }

        try {
            mActivityManagerSingleton = ReflectUtil.get(targetClass, targetField);
            mActivityManager = ReflectUtil.invoke(mActivityManagerSingleton, "get");
        } catch (Exception e) {
            LogUtil.printErrStackTrace(TAG, e, null);
        }
    }

    public synchronized void replaceActivityManagerService() {
        if (!mReplaced) {
            try {
                Object proxy = Proxy.newProxyInstance(mActivityManager.getClass().getClassLoader(),
                        mActivityManager.getClass().getInterfaces(), this);
                ReflectUtil.set(mActivityManagerSingleton, "mInstance", proxy);
                mReplaced = true;
            } catch (Exception e) {
                LogUtil.printErrStackTrace(TAG, e, null);
            }
        }
    }

    public synchronized void restoreActivityManagerService() {
        if (mReplaced) {
            try {
                ReflectUtil.set(mActivityManagerSingleton, "mInstance", mActivityManager);
                mReplaced = false;
            } catch (Exception e) {
                LogUtil.printErrStackTrace(TAG, e, null);
            }
        }
    }

    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
        switch (method.getName()) {
            case "startActivity":
            case "startService":
            case "broadcastIntent":
                LogUtil.d(TAG, "%s: set applicationThread null", method.getName());
                args[0] = null; // applicationThread = null;
                break;
        }
        return method.invoke(mActivityManager, args);
    }

}
