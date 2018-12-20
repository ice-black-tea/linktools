package android.tools.command;

import android.content.pm.ActivityInfo;
import android.content.pm.ComponentInfo;
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

import java.security.Provider;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

@Parameters(commandDescription = "")
public class PackageCommand extends Command {

    @Parameter(names = {"-l", "--list"}, order = 0, description = "List packages")
    public AppType list = null;

    @Parameter(names = {"-s", "--simplify"}, order = 1, description = "Display Simplified information.")
    private boolean simplify = false;

    @Parameter(names = {"-c", "--component"}, order = 100, description = "Display components.")
    private Component component = null;

    @Parameter(names = {"-f", "--fuzz"}, order = 101, description = "Fuzz components (not implemented)")
    private boolean fuzz = false;

    @Override
    public void run() {
        List<PackageInfo> packageInfos = PackageUtil.getInstalledPackages(list);
        Collections.sort(packageInfos, new Comparator<PackageInfo>() {
            @Override
            public int compare(PackageInfo o1, PackageInfo o2) {
                return o1.packageName.compareTo(o2.packageName);
            }
        });

        for (PackageInfo packageInfo : packageInfos) {
            Package pkg = new Package(packageInfo);
            pkg.print(simplify);
            if (component != null) {
                pkg.fuzz(component);
                Output.out.println();
            }
        }
    }

    private enum Component {
        all,
        exported,
        dangerous
    }

    private static class Package {

        PackageInfo info;

        Package(PackageInfo info) {
            this.info = info;
        }

        void print(boolean simplify) {
            if (!simplify) {
                Output.out.println("[*] %s: [uid=%d, name=%s, path=%s, system=%s]",
                        info.packageName,
                        info.applicationInfo.uid,
                        PackageUtil.getApplicationName(info),
                        info.applicationInfo.publicSourceDir,
                        PackageUtil.isSystemPackage(info) ? "true" : "false");
            } else {
                Output.out.println(info.packageName);
            }
        }

        void fuzz(Component component) {
            if (info.activities != null) {
                for (ActivityInfo info : info.activities) {
                    if (component == Component.exported && !exported(info)) {
                        continue;
                    } else if (component == Component.dangerous  && !dangerous(info)) {
                        continue;
                    }
                    Output.out.indent(4).println("[A] %s", info.name);
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

            if (info.services != null) {
                for (ServiceInfo info : info.services) {
                    if (component == Component.exported && !exported(info)) {
                        continue;
                    } else if (component == Component.dangerous  && !dangerous(info)) {
                        continue;
                    }
                    Output.out.indent(4).println("[S] %s", info.name);
                }
            }

            if (info.receivers != null) {
                for (ActivityInfo info : info.receivers) {
                    if (component == Component.exported && !exported(info)) {
                        continue;
                    } else if (component == Component.dangerous  && !dangerous(info)) {
                        continue;
                    }
                    Output.out.indent(4).println("[R] %s", info.name);
                }
            }

            if (info.providers != null) {
                for (ProviderInfo info : info.providers) {
                    if (component == Component.exported && !exported(info)) {
                        continue;
                    } else if (component == Component.dangerous  && !dangerous(info)) {
                        continue;
                    }
                    Output.out.indent(4).println("[P] %s", info.name);
                }
            }
        }

        boolean exported(ComponentInfo ci) {
            return ci.exported;
        }

        boolean dangerous(ComponentInfo ci) {
            if (exported(ci)) {
                return false;
            }
            if (ci instanceof ActivityInfo) {
                return PermissionUtil.isDangerousOrNormal(((ActivityInfo) ci).permission);
            } else if (ci instanceof ServiceInfo) {
                return PermissionUtil.isDangerousOrNormal(((ServiceInfo) ci).permission);
            } else if (ci instanceof ProviderInfo) {
                return PermissionUtil.isDangerousOrNormal(((ProviderInfo) ci).readPermission)
                        && !PermissionUtil.isDangerousOrNormal(((ProviderInfo) ci).writePermission);
            }
            return false;
        }

    }
}
