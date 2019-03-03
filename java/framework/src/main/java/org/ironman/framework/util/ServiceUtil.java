package org.ironman.framework.util;

import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.os.ServiceManager;

public class ServiceUtil {

    public static class Callback {
        public void onBeforeTransact(IBinder binder, Parcel data) throws Exception { }
        public void onAfterTransact(IBinder binder, boolean result, Parcel reply) throws Exception { }
    }

    public static boolean transact(String service, int code, Callback callback) throws Exception {
        return transact(ServiceManager.getService(service), code, callback);
    }

    public static boolean transact(IBinder binder, int code, Callback callback) throws Exception {
        boolean result = false;
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            callback.onBeforeTransact(binder, data);
            result = binder.transact(code, data, reply, 0);
            reply.readException();
            callback.onAfterTransact(binder, result, reply);
        } finally {
            data.recycle();
            reply.recycle();
        }
        return result;
    }

}
