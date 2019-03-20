package android.tools;

import android.tools.command.Command;
import android.tools.processor.CommandUtils;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;

import org.ironman.framework.util.LogUtil;


public class Main {

    private static final String TAG = "android-tools";
    private static final String FLAG_BEGIN = " -*- output -*- by -*- android -*- tools -*- begin -*- ";
    private static final String FLAG_END = " -*- output -*- by -*- android -*- tools -*- end -*- ";

    private static final String PROGRAM_NAME = String.format(
            "CLASSPATH=%s app_process / %s",
            "`ls /sdcard/android-tools/*/dex/android-tools-*.apk`",
            Main.class.getName()
    );

    @Parameter(names = "--add-flag", hidden = true)
    private boolean flag = false;

    private static void parseArgs(String[] args) throws Throwable {
        Main main = new Main();

        JCommander.Builder builder = JCommander.newBuilder().addObject(main);
        builder.programName(PROGRAM_NAME);
        CommandUtils.addCommands(builder);
        JCommander commander = builder.build();
        commander.parse(args);

        int index = 0;
        if (main.flag) {
            index++;
            Output.out.print(FLAG_BEGIN);
        }

        if (args.length > index) {
            JCommander jCommander = commander.getCommands().get(args[index]);
            if (jCommander != null) {
                ((Command) jCommander.getObjects().get(0)).run();
            } else {
                commander.usage();
            }
        } else {
            commander.usage();
        }

        if (main.flag) {
            Output.out.print(FLAG_END);
        }
    }

    @SuppressWarnings("ConstantConditions")
    public static void main(String[] args) {
        if (Output.out != null) {
            Output.out.setPrintStream(System.out);
        }
        if (Output.err != null) {
            Output.err.setPrintStream(System.err);
        }

        try {
            parseArgs(args);
        } catch (Throwable th) {
            Output.err.print(th.getMessage());
            LogUtil.printStackTrace(TAG, th, null);
            System.exit(-1);
        }
    }

}
