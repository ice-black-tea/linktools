package android.tools.command;

import android.content.pm.ActivityInfo;
import android.content.pm.PackageInfo;
import android.content.pm.ProviderInfo;
import android.content.pm.ServiceInfo;
import android.tools.Command;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

import org.ironman.framework.bean.AppType;
import org.ironman.framework.util.PackageUtil;
import org.ironman.framework.util.PermissionUtil;

import java.util.Collections;
import java.util.Comparator;
import java.util.List;

@Parameters(commandDescription = "")
public class PackageCommand extends Command {

    @Parameter(names = {"-t", "--type"}, order = 0, description = "package type.")
    private AppType type = AppType.all;

    @Parameter(names = {"-e", "--export"}, order = 5, description = "Show exported company only.")
    private boolean export = false;

    @Parameter(names = {"-d", "--dangerous"}, order = 6, description = "Show dangerous and normal permission only.")
    private boolean dangerous = false;

    @Parameter(names = {"-f", "--fuzz"}, order = 7, description = "fuzz components (not implemented)")
    private boolean fuzz = false;

    @Override
    public void run() {
        List<PackageInfo> packageInfos = PackageUtil.getInstalledPackages(type);
        Collections.sort(packageInfos, new Comparator<PackageInfo>() {
            @Override
            public int compare(PackageInfo o1, PackageInfo o2) {
                return o1.packageName.compareTo(o2.packageName);
            }
        });


        for (PackageInfo packageInfo : packageInfos) {
            System.out.println(String.format("[%s] %s (uid=%d, name=%s, path=%s)",
                    PackageUtil.isSystemPackage(packageInfo) ? "*" : "-",
                    packageInfo.packageName,
                    packageInfo.applicationInfo.uid,
                    PackageUtil.getApplicationName(packageInfo),
                    packageInfo.applicationInfo.publicSourceDir));

            if (packageInfo.activities != null) {
                for (ActivityInfo info : packageInfo.activities) {
                    if (export && !info.exported) {
                        continue;
                    }
                    if (dangerous && !PermissionUtil.isDangerousOrNormal(info.permission)) {
                        continue;
                    }
                    System.out.println(String.format("    [A] %s", info.name));
//                    try {
//                        Intent intent = new Intent(Intent.ACTION_VIEW);
//                        intent.addFlags(-1);
//                        intent.addCategory(Intent.CATEGORY_LAUNCHER);
//                        intent.setComponent(new ComponentName(info.packageName, info.name));
//                        AtEnvironment.getApplication().startActivity(intent);
//                    } catch (Exception e) {
//                        System.IO.print(" --> ");
//                        System.IO.print(e.getClass().getName());
//                        System.IO.print(": ");
//                        System.IO.print(e.getMessage());
//                        System.IO.println();
//                        System.IO.println(Log.getStackTraceString(e));
//                    } finally {
//                        System.IO.println();
//                    }
                }
            }

            if (packageInfo.services != null) {
                for (ServiceInfo info : packageInfo.services) {
                    if (export && !info.exported) {
                        continue;
                    }
                    if (dangerous && !PermissionUtil.isDangerousOrNormal(info.permission)) {
                        continue;
                    }
                    System.out.println(String.format("    [S] %s", info.name));
                }
            }

            if (packageInfo.receivers != null) {
                for (ActivityInfo info : packageInfo.receivers) {
                    if (export && !info.exported) {
                        continue;
                    }
                    if (dangerous && !PermissionUtil.isDangerousOrNormal(info.permission)) {
                        continue;
                    }
                    System.out.println(String.format("    [R] %s", info.name));
                }
            }

            if (packageInfo.providers != null) {
                for (ProviderInfo providerInfo : packageInfo.providers) {
                    if (export && !providerInfo.exported) {
                        continue;
                    }
                    if (dangerous && !PermissionUtil.isDangerousOrNormal(providerInfo.readPermission)
                        && !PermissionUtil.isDangerousOrNormal(providerInfo.writePermission)) {
                        continue;
                    }
                    System.out.println(String.format("    [P] %s", providerInfo.name));
                }
            }
        }
    }
}
