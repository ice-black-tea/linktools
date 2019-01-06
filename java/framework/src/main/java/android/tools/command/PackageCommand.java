package android.tools.command;

import android.content.pm.PackageInfo;
import android.tools.Output;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;
import com.google.gson.Gson;

import org.ironman.framework.bean.JPackage;
import org.ironman.framework.util.PackageUtil;

import java.util.ArrayList;
import java.util.List;

@Parameters(commandNames = "package")
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

        List<JPackage> packages = new ArrayList<>(packageInfos.size());
        for (PackageInfo packageInfo : packageInfos) {
            packages.add(new JPackage(packageInfo));
        }

        Output.out.println(new Gson().toJson(packages));
    }
}
