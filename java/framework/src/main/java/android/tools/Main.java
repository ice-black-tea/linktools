package android.tools;

import android.tools.command.ActivityCommand;
import android.tools.command.PackageCommand;
import android.tools.command.ServiceCommand;
import android.util.Log;

import com.beust.jcommander.JCommander;

import org.ironman.framework.util.LogUtil;

public class Main {

    private static void parseArgs(String[] args) throws Throwable {
        Main main = new Main();
        ActivityCommand activityCommand = new ActivityCommand();
        PackageCommand packageCommand = new PackageCommand();
        ServiceCommand serviceCommand = new ServiceCommand();

        JCommander commander = JCommander.newBuilder()
                .addObject(main)
                .addCommand("activity", activityCommand)
                .addCommand("package", packageCommand)
                .addCommand("service", serviceCommand)
                .build();

        if (args.length == 0) {
            commander.usage();
            System.exit(-1);
        }

        commander.parse(args);
        switch (args[0]) {
            case "activity":
                activityCommand.run();
                break;
            case "package":
                packageCommand.run();
                break;
            case "service":
                serviceCommand.run();
                break;
            default:
                commander.usage();
                break;
        }
    }

    public static void main(String[] args) {
        try {
            parseArgs(args);
        } catch (Throwable th) {
            Output.err.println(th);
        }
    }


    private static class LogImpl implements LogUtil.LogImpl {

        @Override
        public void v(final String tag, final String format, final Object... args) {
            Output.out.println((args == null || args.length == 0) ? format : String.format(format, args));
        }

        @Override
        public void i(final String tag, final String format, final Object... args) {
            Output.out.println((args == null || args.length == 0) ? format : String.format(format, args));
        }

        @Override
        public void d(final String tag, final String format, final Object... args) {
            Output.out.println((args == null || args.length == 0) ? format : String.format(format, args));
        }

        @Override
        public void w(final String tag, final String format, final Object... args) {
            Output.out.println((args == null || args.length == 0) ? format : String.format(format, args));
        }

        @Override
        public void e(final String tag, final String format, final Object... args) {
            Output.err.println((args == null || args.length == 0) ? format : String.format(format, args));
        }

        @Override
        public void printErrStackTrace(String tag, Throwable tr, String format, Object... args) {
            String log = (args == null || args.length == 0) ? format : String.format(format, args);
            if (log == null) {
                log = "";
            }
            Output.err.println(log + "  " + Log.getStackTraceString(tr));
        }
    }

}
