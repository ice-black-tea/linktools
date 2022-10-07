package android.tools.command;

import android.content.pm.PackageInfo;
import android.tools.Output;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import com.google.gson.Gson;

import org.ironman.framework.bean.app.FPackage;
import org.ironman.framework.util.PackageUtil;

import java.util.ArrayList;
import java.util.List;

@Parameters(commandNames = "package")
public class PackageCommand extends Command {

    @Parameter(names = {"-p", "--packages"}, variableArity = true, order = 0,
               description = "List packages, list all packages if not set")
    private List<String> packages = new ArrayList<>();

    @Parameter(names = {"--system"}, order = 0,
            description = "Display system packages only")
    private boolean system = false;

    @Parameter(names = {"--non-system"}, order = 0,
            description = "Display non-system packages only")
    private boolean non_system = false;

    @Parameter(names = {"-b", "--basic-info"}, order = 0,
               description = "Display basic info only")
    private boolean basic = false;

    @Override
    public void run() {
        List<PackageInfo> packageInfos;
        if (packages.size() > 0) {
            packageInfos = PackageUtil.getPackages(packages.toArray(new String[packages.size()]));
        } else {
            packageInfos = PackageUtil.getInstalledPackages();
        }

        List<FPackage> packages = new ArrayList<>(packageInfos.size());
        for (PackageInfo packageInfo : packageInfos) {
            if (system) {
                if (!PackageUtil.isSystemApp(packageInfo)) {
                    continue;
                }
            } else if (non_system) {
                if (PackageUtil.isSystemApp(packageInfo)) {
                    continue;
                }
            }
            packages.add(new FPackage(packageInfo, basic));
        }

        Output.out.println(new Gson().toJson(packages));
    }
}
