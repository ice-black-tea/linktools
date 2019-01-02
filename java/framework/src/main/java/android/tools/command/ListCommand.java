package android.tools.command;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

/**
 * Created by hu on 18-12-29.
 */

@Parameters(commandNames = "list")
public class ListCommand extends Command {

    private enum PackageType {
        packages,
        system_packages,
        non_system_packages,
    }

    private enum DetailType {
        components,
        exported_components,
        dangerous_normal_components,

        permissions,
        dangerous_normal_permissions,
    }

    @Parameter(names = {"-p", "--package"}, order = 0, description = "Package1 packageType needs to be listed")
    private PackageType packageType = PackageType.packages;

    @Parameter(names = {"-t", "--type"}, order = 0, description = "Package1 packageType needs to be listed")
    private DetailType dd = null;

    @Override
    public void run() {
        switch (packageType) {
            case packages:
            case system_packages:
            case non_system_packages:
        }
    }
}
