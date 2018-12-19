package android.tools.command;

import android.content.pm.ActivityInfo;
import android.content.pm.PackageInfo;
import android.content.pm.ProviderInfo;
import android.content.pm.ServiceInfo;
import android.tools.Command;
import android.tools.Output;

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

    enum Component {
        export,
        dangerous
    }

    @Parameter(names = {"-t", "--type"}, order = 0, description = "Package type.")
    private AppType type = AppType.all;

    @Parameter(names = {"-c", "--component"}, order = 4, description = "Show components.")
    private Component component = null;

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
            Output.out.println("[*] %s\n    uid=%d, name=%s, path=%s, system=%s",
                    packageInfo.packageName,
                    packageInfo.applicationInfo.uid,
                    PackageUtil.getApplicationName(packageInfo),
                    packageInfo.applicationInfo.publicSourceDir,
                    PackageUtil.isSystemPackage(packageInfo) ? "true" : "false");

            if (component == null) {
                continue;
            }

            if (packageInfo.activities != null) {
                for (ActivityInfo info : packageInfo.activities) {
                    if ((component == Component.export || component == Component.dangerous) && !info.exported) {
                        continue;
                    }
                    if (component == Component.dangerous && !PermissionUtil.isDangerousOrNormal(info.permission)) {
                        continue;
                    }
                    Output.out.println("    [A] %s", info.name);
//                    try {
//                        Intent intent = new Intent(Intent.ACTION_VIEW);
//                        intent.addFlags(-1);
//                        intent.addCategory(Intent.CATEGORY_LAUNCHER);
//                        intent.setComponent(new ComponentName(info.packageName, info.name));
//                        AtEnvironment.getApplication().startActivity(intent);
//                    } catch (Exception e) {
//                        System.Output.print(" --> ");
//                        System.Output.print(e.getClass().getName());
//                        System.Output.print(": ");
//                        System.Output.print(e.getMessage());
//                        System.Output.println();
//                        System.Output.println(Log.getStackTraceString(e));
//                    } finally {
//                        System.Output.println();
//                    }
                }
            }

            if (packageInfo.services != null) {
                for (ServiceInfo info : packageInfo.services) {
                    if ((component == Component.export || component == Component.dangerous) && !info.exported) {
                        continue;
                    }
                    if (component == Component.dangerous && !PermissionUtil.isDangerousOrNormal(info.permission)) {
                        continue;
                    }
                    Output.out.println("    [S] %s", info.name);
                }
            }

            if (packageInfo.receivers != null) {
                for (ActivityInfo info : packageInfo.receivers) {
                    if ((component == Component.export || component == Component.dangerous) && !info.exported) {
                        continue;
                    }
                    if (component == Component.dangerous && !PermissionUtil.isDangerousOrNormal(info.permission)) {
                        continue;
                    }
                    Output.out.println("    [R] %s", info.name);
                }
            }

            if (packageInfo.providers != null) {
                for (ProviderInfo info : packageInfo.providers) {
                    if ((component == Component.export || component == Component.dangerous) && !info.exported) {
                        continue;
                    }
                    if (component == Component.dangerous && !PermissionUtil.isDangerousOrNormal(info.readPermission)
                        && !PermissionUtil.isDangerousOrNormal(info.writePermission)) {
                        continue;
                    }
                    Output.out.println("    [P] %s", info.name);
                }
            }

            Output.out.println();
        }
    }
}
