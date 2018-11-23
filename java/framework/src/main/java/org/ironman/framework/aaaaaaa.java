package org.ironman.framework;

import android.os.IBinder;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.util.Log;

public class aaaaaaa {

    public static void main(String[] args) {

        try {
            for (String s : ServiceManager.listServices()) {
                IBinder service = ServiceManager.getService(s);
                Log.d("dsadsadsa", s + "      " + service);
            }
        } catch (RemoteException e) {
            e.printStackTrace();
        }

    }


}
