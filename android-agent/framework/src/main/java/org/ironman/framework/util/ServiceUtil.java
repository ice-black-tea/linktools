package org.ironman.framework.util;

import android.os.IBinder;
import android.os.Parcel;
import android.os.Process;
import android.os.ServiceManager;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

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









    public static class ServiceUsage{
        static final int FLAG_NODE_USER = 0x1;
        static final int FLAG_NODE_OWNER = 0x2;
        String path;
        int usage;
        int pid;

        public ServiceUsage(String path, int usage, int pid) {
            this.path = path;
            this.usage = usage;
            this.pid = pid;
        }

        boolean isServiceOwner()
        {
            return (usage & FLAG_NODE_OWNER) != 0;
        }
        @Override
        public String toString() {
            if( (usage & ServiceUsage.FLAG_NODE_OWNER) != 0)
            {
                return String.format("Owner: %d\t%s", pid, path);
            }
            else if ( (usage & ServiceUsage.FLAG_NODE_USER) != 0)
            {
                return String.format("User: %d\t%s", pid, path);
            }
            else{
                //this should not happen
                return "???";
            }
        }
    }

    public static int getSelfHoldingNode() throws IOException {
        String path = "/sys/kernel/debug/binder/proc/" + Process.myPid();
        String binderstat = FileUtil.readString(path);
        System.out.println(binderstat);
        return extractStatAndGetServiceNode(binderstat);
    }

    protected static int extractStatAndGetServiceNode(String binderstat) {
        //find first "context binder"
        //first ref is usually service manager
        int svcMgrNodeIndex = binderstat.indexOf("context binder");
        if(svcMgrNodeIndex == -1)
        {
            throw new IllegalArgumentException("unreachable: the process does not have context binder");
        }
        svcMgrNodeIndex = binderstat.indexOf("node", svcMgrNodeIndex + 1);
        if(svcMgrNodeIndex == -1)
        {
            //wtf? cannot find any node?
            throw new IllegalArgumentException("cannot find any node in binder stat");
        }
        //next ref is the service we opened
        int svcNodeIndex = binderstat.indexOf("node", svcMgrNodeIndex + 1);
        Scanner scanner = new Scanner(binderstat.substring(svcNodeIndex + 1));
        scanner.next();
        return scanner.nextInt();
    }

    private static List<ServiceUsage> iterateProcFs(int nodeid)
    {
        List<ServiceUsage> usageList = new ArrayList<>();
        File procroot = new File("/sys/kernel/debug/binder/proc/");
        for(File statFile: procroot.listFiles())
        {
            try {
                String binderstat = FileUtil.readString(statFile.getPath());
                int pid = Integer.parseInt(statFile.getName());
                int ret = procUserOrOwner(binderstat, nodeid);
                if(ret != 0)
                {
                    String procinfo = getProcessNameByPid(pid);
                    usageList.add(new ServiceUsage(procinfo, ret, pid));
                }
            } catch (IOException e) {
                //e.printStackTrace();
                e.printStackTrace();
                //this pid may have died while we iterate. ignore exception
            }
        }
        return usageList;
    }

    private static String getProcessNameByPid(int pid) throws IOException {
        File procExeFile = new File(String.format("/proc/%d/exe", pid));
        String exePath = procExeFile.toPath().toRealPath().toString();

        String cmdline = FileUtil.readString(String.format("/proc/%d/cmdline", pid));
        //special handle for app_process
        if(exePath.contains("app_process"))
        {
            //use cmdline instead
            return cmdline;
        }
        return cmdline + "\t" + exePath;
    }

    static int procUserOrOwner(String binderstat, int nodeid)
    {
        int beginindex = binderstat.indexOf("context binder");
        int endindex = binderstat.indexOf("binder proc state", beginindex + 15);
        int result = 0;

        String symbol = String.format("node %d", nodeid);
        if(beginindex == -1)
        {
            //this process only holds one kind of binder, but not what we desired
        }
        else{
            if(endindex != -1)
            {
                binderstat = binderstat.substring(beginindex+1, endindex);
            }
            for(String line: binderstat.split("\n"))
            {
                line = line.trim();
                if(line.contains(symbol + " ") || line.contains(symbol + ":"))
                {
                    if(line.startsWith("ref "))
                    {
                        //this process uses this binder node

                        result |= ServiceUsage.FLAG_NODE_USER;
                    }
                    else if(line.startsWith("node "))
                    {
                        //this process holds this binder node

                        result |= ServiceUsage.FLAG_NODE_OWNER;
                    }
                    else {
                        //???wtf
                    }
                }
            }
        }
        return result;
    }

}
