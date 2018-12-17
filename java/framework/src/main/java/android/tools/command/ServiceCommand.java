package android.tools.command;

import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;
import android.os.ServiceManager;
import android.tools.Command;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

import java.util.Arrays;

/**
 * Created by hu on 18-12-18.
 */

@Parameters(commandDescription = "")
public class ServiceCommand extends Command {

    @Parameter(names = {"-f", "--fuzz"}, order = 1, description = "fuzz system service")
    private boolean fuzz = false;

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
            System.out.print("[*] " + service);

            IBinder binder = null;
            String desc = null;
            try {
                binder = ServiceManager.getService(service);
                desc = binder.getInterfaceDescriptor();
                System.out.print(" (" + desc + ") ");
            } catch (Exception e) {
                e.printStackTrace();
            }

            if (binder == null) {
                continue;
            }

            Parcel data = Parcel.obtain();
            data.writeInterfaceToken(desc);
//            while (data.dataSize() < 0x1000) {
//                data.writeInt(0);
//            }

            for (int i = 1; i < 1000; i++) {
                try {
                    Parcel reply = Parcel.obtain();
                    binder.transact(i, data, reply, 0);
                    reply.readException();
                    if (reply.dataPosition() < reply.dataSize()) {
                        System.out.println(Arrays.toString(reply.marshall()));
                    }
                    reply.recycle();
                } catch (Exception e) {
                    System.err.println(i + "  " + e.getClass() + "  " + e.getMessage());
                    e.printStackTrace();
                }
            }
            data.recycle();
        }
    }
}
