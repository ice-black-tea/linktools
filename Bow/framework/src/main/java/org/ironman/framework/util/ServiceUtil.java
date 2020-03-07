package org.ironman.framework.util;

import android.os.IBinder;
import android.os.Parcel;
import android.os.ServiceManager;

public class ServiceUtil {

    private static final String TAG = ServiceUtil.class.getSimpleName();

    public static abstract class Callback {

        public void onBeforeTransact(IBinder binder, Parcel data) throws Exception {
            data.writeInterfaceToken(binder.getInterfaceDescriptor());
        }

        public void onAfterTransact(IBinder binder, boolean result, Parcel reply) throws Exception {
            reply.readException();
        }

        public void onError(Exception e) throws Exception {
            throw e;
        }
    }

    public static boolean transact(String service, int code) throws Exception {
        return transact(ServiceManager.getService(service), code, null);
    }

    public static boolean transact(IBinder binder, int code) throws Exception {
        return transact(binder, code, null);
    }

    public static boolean transact(String service, int code, Callback callback) throws Exception {
        return transact(ServiceManager.getService(service), code, callback);
    }

    public static boolean transact(IBinder binder, int code, Callback callback) throws Exception {
        boolean result = false;
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            if (callback != null) {
                try {
                    callback.onBeforeTransact(binder, data);
                    result = binder.transact(code, data, reply, 0);
                    callback.onAfterTransact(binder, result, reply);
                } catch (Exception th) {
                    callback.onError(th);
                }
            } else {
                result = binder.transact(code, data, reply, 0);
            }
        } finally {
            data.recycle();
            reply.recycle();
        }
        return result;
    }

}
