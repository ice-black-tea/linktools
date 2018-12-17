package android.tools.command;

import android.content.pm.ActivityInfo;
import android.content.pm.PackageInfo;
import android.content.pm.ProviderInfo;
import android.content.pm.ServiceInfo;
import android.tools.Command;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

import org.ironman.framework.bean.AppType;
import org.ironman.framework.helper.PackageHelper;
import org.ironman.framework.helper.PermissionHelper;

import java.util.Collections;
import java.util.Comparator;
import java.util.List;

@Parameters(commandDescription = "")
public class PackageCommand extends Command {

    @Parameter(names = {"-t", "--type"}, order = 0, description = "package type.")
    private AppType type = AppType.all;

    @Parameter(names = {"-a", "--activity"}, order = 1, description = "Show activity info.")
    private boolean activity = false;

    @Parameter(names = {"-s", "--service"}, order = 2, description = "Show service info.")
    private boolean service = false;

    @Parameter(names = {"-r", "--receiver"}, order = 3, description = "Show receiver info.")
    private boolean receiver = false;

    @Parameter(names = {"-p", "--provider"}, order = 4, description = "Show provider info.")
    private boolean provider = false;

    @Parameter(names = {"-e", "--export"}, order = 5, description = "Show exported company only.")
    private boolean export = false;

    @Parameter(names = {"-d", "--dangerous"}, order = 6, description = "Show dangerous and normal permission only.")
    private boolean dangerous = false;

    @Parameter(names = {"-f", "--fuzz"}, order = 7, description = "fuzz")
    private boolean fuzz = false;

    @Override
    public void run() {
        PackageHelper packageHelper = PackageHelper.get();
        PermissionHelper permissionHelper = PermissionHelper.get();

        List<PackageInfo> packageInfos = packageHelper.getInstalledPackages(type);
        Collections.sort(packageInfos, new Comparator<PackageInfo>() {
            @Override
            public int compare(PackageInfo o1, PackageInfo o2) {
                return o1.packageName.compareTo(o2.packageName);
            }
        });

        for (PackageInfo packageInfo : packageInfos) {
            System.out.println(String.format("[%s] %s (uid=%d, name=%s, path=%s)",
                    packageHelper.isSystemPackage(packageInfo) ? "S" : "N",
                    packageInfo.packageName,
                    packageInfo.applicationInfo.uid,
                    packageHelper.getApplicationName(packageInfo),
                    packageInfo.applicationInfo.publicSourceDir));

            if (activity && packageInfo.activities != null) {
                for (ActivityInfo activityInfo : packageInfo.activities) {
                    if (export && !activityInfo.exported) {
                        continue;
                    }
                    if (dangerous && !permissionHelper.isDangerousOrNormal(activityInfo.permission)) {
                        continue;
                    }
                    System.out.println(String.format("    [A] %s", activityInfo.name));
                }
            }

            if (service && packageInfo.services != null) {
                for (ServiceInfo serviceInfo : packageInfo.services) {
                    if (export && !serviceInfo.exported) {
                        continue;
                    }
                    if (dangerous && !permissionHelper.isDangerousOrNormal(serviceInfo.permission)) {
                        continue;
                    }
                    System.out.println(String.format("    [S] %s", serviceInfo.name));
                }
            }

            if (receiver && packageInfo.receivers != null) {
                for (ActivityInfo activityInfo : packageInfo.receivers) {
                    if (export && !activityInfo.exported) {
                        continue;
                    }
                    if (dangerous && !permissionHelper.isDangerousOrNormal(activityInfo.permission)) {
                        continue;
                    }
                    System.out.println(String.format("    [R] %s", activityInfo.name));
                }
            }

            if (provider && packageInfo.providers != null) {
                for (ProviderInfo providerInfo : packageInfo.providers) {
                    if (export && !providerInfo.exported) {
                        continue;
                    }
                    if (dangerous && !permissionHelper.isDangerousOrNormal(providerInfo.readPermission)
                        && !permissionHelper.isDangerousOrNormal(providerInfo.writePermission)) {
                        continue;
                    }
                    System.out.println(String.format("    [P] %s", providerInfo.name));
                }
            }
        }
    }
}
