package android.tools.command;

import android.content.pm.PackageInfo;
import android.tools.Output;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

import org.ironman.framework.bean.app.FPackage;
import org.ironman.framework.util.GsonUtil;
import org.ironman.framework.util.PackageUtil;

import java.util.ArrayList;
import java.util.List;

@Parameters(commandNames = "package")
public class PackageCommand extends Command {

    @Parameter(names = {"-p", "--packages"}, variableArity = true, order = 0,
               description = "List packages, list all packages if not set")
    private List<String> packages = new ArrayList<>();

    @Parameter(names = {"-u", "--uids"}, variableArity = true, order = 0,
            description = "List packages, list packages with specified uids if not set")
    private List<Integer> uids = new ArrayList<>();

    @Parameter(names = {"--system"}, order = 0,
            description = "Display system packages only")
    private boolean system = false;

    @Parameter(names = {"--non-system"}, order = 0,
            description = "Display non-system packages only")
    private boolean nonSystem = false;

    @Parameter(names = {"-s", "--simple"}, order = 0,
               description = "Display basic info only")
    private boolean simple = false;

    @Override
    public void run() {
        List<PackageInfo> packageInfos;
        if (packages.size() > 0) {
            packageInfos = PackageUtil.getPackages(packages);
        } else if (uids.size() > 0) {
            packageInfos = PackageUtil.getPackagesForUid(uids);
        } else {
            packageInfos = PackageUtil.getInstalledPackages();
        }

        List<FPackage> packages = new ArrayList<>(packageInfos.size());
        for (PackageInfo packageInfo : packageInfos) {
            if (system && !PackageUtil.isSystemApp(packageInfo)) {
                // ignore
            } else if (nonSystem && PackageUtil.isSystemApp(packageInfo)) {
                // ignore
            } else {
                packages.add(new FPackage(packageInfo, simple));
            }
        }

        Output.out.println(GsonUtil.toJson(packages));
    }
}
