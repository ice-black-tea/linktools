package android.tools.command;

import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.tools.Command;
import android.tools.Output;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by hu on 18-12-18.
 */

@Parameters(commandDescription = "")
public class ServiceCommand extends Command {

    @Parameter(names = {"-f", "--fuzz"}, order = 1, variableArity = true, description = "Fuzz system service")
    public List<String> fuzz = new ArrayList<>();

    @Parameter(names = {"-e", "--except"}, order = 1, variableArity = true, description = "Fuzz system service")
    public boolean except = false;

    @Override
    public void run() {
        String[] services = null;

        try {
            services = ServiceManager.listServices();
        } catch (RemoteException e) {
            e.printStackTrace();
        }

        if (services == null || services.length == 0) {
            return;
        }

        for (String service : services) {

            IBinder binder = null;
            String desc = "";
            try {
                binder = ServiceManager.getService(service);
                desc = binder.getInterfaceDescriptor();
            } catch (Exception e) {
                // e.printStackTrace();
            }

            Output.out.println(">>> %s [%s]", service, desc);

            boolean contains = fuzz.contains(service);
            if (binder == null || (!except && !contains)) {
                Output.out.println();
                continue;
            }

            Parcel data = Parcel.obtain();
            data.writeInterfaceToken(desc);
//            while (data.dataSize() < 0x1000) {
//                data.writeInt(0);
//            }

            for (int i = 1; i <= 1000; i++) {
                try {
                    Parcel reply = Parcel.obtain();
                    if (binder.transact(i, data, reply, 0)) {
                        try {
                            reply.readException();
                            Output.out.println("    %d", i);
                            reply.recycle();
                        } catch (Exception e) {
                            Output.out.println("    %d -> %s: %s", i, e.getClass().getName(), e.getMessage());
                        }
                    }
                } catch (RemoteException e) {
                    Output.out.println("    %d -> %s: %s", i, e.getClass().getName(), e.getMessage());
                } catch (Exception e) {
                    // e.printStackTrace();
                }
            }
            data.recycle();

            Output.out.println();
        }
    }
}
