package org.ironman.framework;

import android.app.ActivityThread;
import android.app.Application;
import android.os.Looper;

public final class AtEnvironment {
    
    private static Application sApplication = null;
    
    public static Application getApplication() {
        
        if (sApplication != null) {
            return sApplication;
        }
        
        if (Looper.getMainLooper() == null) {
            Looper.prepareMainLooper();
        }
        
        if (ActivityThread.currentActivityThread() == null) {
            ActivityThread.systemMain();
        }
        
        return sApplication = ActivityThread.currentApplication();
    }
}
