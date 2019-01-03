package android.tools;

import android.tools.command.ActivityCommand;
import android.tools.command.Command;
import android.tools.command.ListCommand;
import android.tools.command.PackageCommand;
import android.tools.command.ServiceCommand;
import android.util.Log;

import com.beust.jcommander.JCommander;

import org.ironman.framework.util.LogUtil;

public class Main {

    private static void parseArgs(String[] args) throws Throwable {
        Main main = new Main();

        JCommander.Builder builder = JCommander.newBuilder().addObject(main);

        builder.addCommand(new ListCommand());
        builder.addCommand(new PackageCommand());
        builder.addCommand(new ActivityCommand());
        builder.addCommand(new ServiceCommand());

        JCommander commander = builder.build();

        if (args.length == 0) {
            commander.usage();
            return;
        }

        commander.parse(args);

        JCommander jCommander = commander.getCommands().get(args[0]);
        if (jCommander != null) {
            Output.out.print(" -- exec main command (output by android-tools) -- ");
            ((Command) jCommander.getObjects().get(0)).run();
        } else {
            commander.usage();
        }
    }

    public static void main(String[] args) {
        try {
            Output.out.setPrintStream(System.out);
            Output.err.setPrintStream(System.err);
            parseArgs(args);
        } catch (Throwable th) {
            Output.err.println(th);
            System.exit(-1);
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
