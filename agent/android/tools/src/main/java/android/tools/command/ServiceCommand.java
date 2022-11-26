package android.tools.command;

import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.tools.Output;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by hu on 18-12-18.
 */

@Parameters(commandNames = "service")
public class ServiceCommand extends Command {

    @Parameter(names = {"-l", "--list"}, order = 0, description = "List all system services")
    private boolean list = false;

    @Parameter(names = {"-s", "--simple"}, order = 1, description = "Display Simplified information.")
    private boolean simple = false;

    @Parameter(names = {"-f", "--fuzz"}, order = 100, variableArity = true, description = "Fuzz system services")
    private List<String> fuzz = new ArrayList<>();

    @Parameter(names = {"-e", "--except-mode"}, order = 101, description = "Fuzz system services (except mode)")
    private boolean except = false;

    @Override
    public void run() {
        String[] services = null;
        try {
            services = ServiceManager.listServices();
        } catch (Exception e) {
            e.printStackTrace();
        }

        if (services == null || services.length == 0) {
            return;
        }

        for (String name : services) {

            boolean needFuzz = inFuzzList(name);
            if (!needFuzz && !list) {
                continue;
            }

            Service service = new Service(name);
            service.print(simple);

            if (service.valid() && needFuzz) {
                service.fuzz();
                Output.out.println();
            }
        }
    }

    private boolean inFuzzList(String service) {
        boolean contains = fuzz.contains(service);
        return !(!except && !contains) && !(except && contains);
    }

    private static class Service {

        String name;
        String desc;
        IBinder binder;

        Service(String name) {
            this.name = name;
            try {
                this.binder = ServiceManager.getService(name);
                this.desc = this.binder.getInterfaceDescriptor();
            } catch (Exception e) {
                this.binder = null;
                this.desc = "";
            }
        }

        boolean valid() {
            return binder != null;
        }

        void print(boolean simplify) {
            if (!simplify) {
                Output.out.println("[*] %s: [%s] -> [%s]", name, desc, binder);
            } else {
                Output.out.println(name);
            }
        }

        void transact(int code, Parcel data, Parcel reply, int flags) {
            try {
                if (!binder.isBinderAlive()) {
                    binder = ServiceManager.getService(name);
                    for (int i = 0; (binder == null || !binder.isBinderAlive()) && i < 50; i++) {
                        Thread.sleep(100);
                        binder = ServiceManager.getService(name);
                    }
                }

                if (binder.transact(code, data, reply, flags)) {
                    try {
                        reply.readException();
                        Output.out.indent(4).println("%d", code);
                        // Thread.sleep(0);
                    } catch (Exception e) {
                        Output.out.indent(4).println("%d -> %s: %s",
                                code, e.getClass().getName(), e.getMessage());
                    }
                }
            } catch (RemoteException e) {
                Output.out.indent(4).println("%d -> %s: %s",
                        code, e.getClass().getName(), e.getMessage() != null);
            } catch (Exception e) {
                // e.printStackTrace();
            }
        }

        void list() {
            Parcel data = Parcel.obtain();
            for (int i = 1; i <= 1000; i++) {
                Parcel reply = Parcel.obtain();
                transact(i, data, reply, 0);
                reply.recycle();
            }
            data.recycle();
        }

        void fuzz() {
            Parcel data = Parcel.obtain();
            data.writeInterfaceToken(desc);
//            while (data.dataSize() < 0x1000) {
//                data.writeInt(0);
//            }

            for (int i = 1; i <= 1000; i++) {
                Parcel reply = Parcel.obtain();
                transact(i, data, reply, 0);
                reply.recycle();
            }
            data.recycle();
        }
    }
}
