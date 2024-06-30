package org.ironman.framework.proxy;

import org.ironman.framework.util.LogUtil;

import java.util.HashMap;
import java.util.Map;

public abstract class AbstractProxy {

    private static final String TAG = ActivityManagerProxy.class.getSimpleName();
    private static final Map<Class<? extends AbstractProxy>, AbstractProxy> sInstances = new HashMap<>();

    private boolean mInit = false;
    private boolean mHooked = false;

    protected abstract void internalInit() throws Exception;
    protected abstract void internalHook() throws Exception;
    protected abstract void internalUnhook() throws Exception;

    protected AbstractProxy() {

    }

    public static <T extends AbstractProxy> T get(Class<T> klass) {
        AbstractProxy proxy = sInstances.get(klass);
        if (proxy == null) {
            try {
                proxy = klass.newInstance();
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
            sInstances.put(klass, proxy);
        }
        return (T) proxy;
    }

    public void hook() {
        if (!mHooked) {
            try {
                if (!mInit) {
                    internalInit();
                    mInit = true;
                }
                internalHook();
                mHooked = true;
            } catch (Exception e) {
                LogUtil.printStackTrace(TAG, e, null);
            }
        }
    }

    public synchronized void unhook() {
        if (mHooked) {
            try {
                internalUnhook();
                mHooked = false;
            } catch (Exception e) {
                LogUtil.printStackTrace(TAG, e, null);
            }
        }
    }

}
