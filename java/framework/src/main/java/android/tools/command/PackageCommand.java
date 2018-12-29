package android.tools.command;

import android.content.pm.ActivityInfo;
import android.content.pm.ComponentInfo;
import android.content.pm.PackageInfo;
import android.content.pm.ProviderInfo;
import android.content.pm.ServiceInfo;
import android.tools.Output;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import com.google.gson.Gson;

import org.ironman.framework.bean.Package;
import org.ironman.framework.util.PackageUtil;
import org.ironman.framework.util.PermissionUtil;

import java.util.ArrayList;
import java.util.List;

@Parameters(commandNames = "package", commandDescription = "")
public class PackageCommand extends Command {

    @Parameter(names = {"-p", "--packages"}, variableArity = true, order = 0,
               description = "List packages, list all packages if not set")
    private List<String> packages = new ArrayList<>();

    @Override
    public void run() {
        List<PackageInfo> packageInfos;
        if (packages.size() > 0) {
            packageInfos = PackageUtil.getPackages(packages.toArray(new String[packages.size()]));
        } else {
            packageInfos = PackageUtil.getInstalledPackages();
        }

        List<Package> packages = new ArrayList<>(packageInfos.size());
        for (PackageInfo packageInfo : packageInfos) {
            packages.add(new Package(packageInfo));
        }

        Output.out.println(new Gson().toJson(packages));
    }














































    private enum Component1 {
        all,
        exported,
        dangerous
    }

    private static class Package1 {

        PackageInfo info;

        Package1(PackageInfo info) {
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

        void fuzz(Component1 component) {
            if (info.activities != null) {
                for (ActivityInfo info : info.activities) {
                    if (component == Component1.exported && !exported(info)) {
                        continue;
                    } else if (component == Component1.dangerous  && !dangerous(info)) {
                        continue;
                    }
                    Output.out.indent(4).println("[A] %s", info.name);

//                    try {
//                        Intent intent = new Intent(Intent.ACTION_VIEW);
//                        intent.addCategory(Intent.CATEGORY_LAUNCHER);
//                        intent.setComponent(new ComponentName(info.packageName, info.name));
//                        ActivityUtil.startActivity(intent);
//                    } catch (Exception e) {
//                        Output.out.print(" --> ");
//                        Output.out.print(e.getClass().getName());
//                        Output.out.print(": ");
//                        Output.out.print(e.getMessage());
//                        Output.out.println();
//                    } finally {
//                        Output.out.println();
//                    }
                }
            }

            if (info.services != null) {
                for (ServiceInfo info : info.services) {
                    if (component == Component1.exported && !exported(info)) {
                        continue;
                    } else if (component == Component1.dangerous  && !dangerous(info)) {
                        continue;
                    }
                    Output.out.indent(4).println("[S] %s", info.name);
                }
            }

            if (info.receivers != null) {
                for (ActivityInfo info : info.receivers) {
                    if (component == Component1.exported && !exported(info)) {
                        continue;
                    } else if (component == Component1.dangerous  && !dangerous(info)) {
                        continue;
                    }
                    Output.out.indent(4).println("[R] %s", info.name);
                }
            }

            if (info.providers != null) {
                for (ProviderInfo info : info.providers) {
                    if (component == Component1.exported && !exported(info)) {
                        continue;
                    } else if (component == Component1.dangerous  && !dangerous(info)) {
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
