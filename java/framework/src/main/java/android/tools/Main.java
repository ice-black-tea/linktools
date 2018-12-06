package android.tools;

import android.tools.command.ActivityCmd;
import android.tools.command.PackageCmd;

import com.android.internal.util.ArrayUtils;
import com.beust.jcommander.JCommander;

import org.ironman.framework.AtEnvironment;
import org.ironman.framework.helper.ActivityHelper;
import org.ironman.framework.helper.PackageHelper;

public class Main {

    private static void parseArgs(String[] args) throws Throwable {
        Main main = new Main();
        ActivityCmd activityCmd = new ActivityCmd();
        PackageCmd packageCmd = new PackageCmd();

        JCommander commander = JCommander.newBuilder()
                .addObject(main)
                .addCommand("activity", activityCmd)
                .addCommand("package", packageCmd)
                .build();
        commander.parse(args);

        if (ArrayUtils.contains(args, "activity")) {
            activityCmd.run();
        } else if (ArrayUtils.contains(args, "package")) {
            packageCmd.run();
        } else {
            commander.usage();
        }
    }

    public static void test() {
        System.out.println("Try to get Application: " + AtEnvironment.getApplication());
        System.out.println("Try to get PackageManager: " + PackageHelper.get().getPackageManager());
        System.out.println("Try to get ActivityManager: " + ActivityHelper.get().getActivityManager());
    }

    public static void main(String[] args) {
        try {
            parseArgs(args);
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

}
