package org.ironman.framework.util;

import android.os.IBinder;
import android.os.Parcel;
import android.os.ServiceManager;

public class ServiceUtil {

    public static class Callback {
        public void onBefore(IBinder binder, Parcel data) { }
        public void onAfter(IBinder binder, boolean result, Parcel reply) { }
    }

    public static boolean transact(String service, int code, Callback callback) throws Exception {
        boolean result = false;
        IBinder binder = ServiceManager.getService(service);
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            callback.onBefore(binder, data);
            result = binder.transact(code, data, reply, 0);
            reply.readException();
            callback.onAfter(binder, result, reply);
        } finally {
            data.recycle();
            reply.recycle();
        }
        return result;
    }

}
