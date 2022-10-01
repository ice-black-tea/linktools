package android.tools;

import android.tools.command.Command;
import android.tools.processor.CommandUtils;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;


public class Main {

    private static final String TAG = "android-tools";

    private static final String PROGRAM_NAME = String.format(
            "CLASSPATH=%s app_process / %s",
            System.getenv("CLASSPATH"),
            Main.class.getName()
    );

    @Parameter(names = "--start-flag", hidden = true)
    private String startFlag = null;

    @Parameter(names = "--end-flag", hidden = true)
    private String endFlag = null;

    private static void parseArgs(String[] args) throws Throwable {
        Main main = new Main();

        JCommander.Builder builder = JCommander.newBuilder().addObject(main);
        builder.programName(PROGRAM_NAME);
        CommandUtils.addCommands(builder);
        JCommander commander = builder.build();
        commander.parse(args);

        try {
            if (main.startFlag != null) {
                Output.out.print(main.startFlag);
            }
            JCommander jCommander = commander.getCommands().get(commander.getParsedCommand());
            if (jCommander != null) {
                ((Command) jCommander.getObjects().get(0)).run();
            } else {
                commander.usage();
            }
        } finally {
            if (main.endFlag != null) {
                Output.out.print(main.endFlag);
            }
        }
    }

    public static void main(String[] args) {
        if (Output.out.getStream() == null && Output.err.getStream() == null) {
            Output.out.setStream(System.out);
            Output.err.setStream(System.err);
        }

        try {
            parseArgs(args);
        } catch (Throwable th) {
            Output.err.print(th.getMessage());
            System.exit(-1);
        }
    }

}
