package android.tools;

import android.annotation.SuppressLint;
import android.tools.processor.CommandUtils;
import android.util.Log;
import com.beust.jcommander.JCommander;

import java.io.File;
import java.io.OutputStream;
import java.io.PrintStream;

import dalvik.system.PathClassLoader;

public class Main {

    private static final String TAG = "android-tools";

    private static final String PROGRAM_NAME = String.format(
            "CLASSPATH=%s app_process / %s",
            System.getenv("CLASSPATH"),
            Main.class.getName()
    );

    private void printLogo() {
        Output.out.println("┌───────────────────────────────────────────────────────┐");
        Output.out.println("│             Output from android.tools.Main            │");
        Output.out.println("└───────────────────────────────────────────────────────┘");
    }

    @SuppressLint("PrivateApi")
    private IPlugin loadPlugin() throws Exception {
        String path = System.getenv("AGENT_PLUGIN_PATH");
        if (path != null) {
            if (!new File(path).exists()) {
                throw new Exception("Plugin not found: " + path);
            }
            PathClassLoader classLoader = new PathClassLoader(path, IPlugin.class.getClassLoader());
            try {
                Class<?> klass = classLoader.loadClass("android.tools.Plugin");
                return (IPlugin) klass.newInstance();
            } catch (ClassNotFoundException e) {
                throw new Exception("Plugin class 'android.tools.Plugin' not found: " + path);
            }
        }
        return null;
    }

    private void internalMain(String[] args) throws Throwable {
        IPlugin plugin = loadPlugin();

        JCommander.Builder builder = JCommander.newBuilder().addObject(this);
        builder.programName(PROGRAM_NAME);
        CommandUtils.addCommands(builder);
        if (plugin != null) {
            plugin.init(builder);
        }
        JCommander commander = builder.build();
        commander.parse(args);

        JCommander jCommander = commander.getCommands().get(commander.getParsedCommand());
        if (jCommander != null) {
            ((ICommand) jCommander.getObjects().get(0)).run();
        } else {
            StringBuilder sb = new StringBuilder();
            commander.getUsageFormatter().usage(sb);
            Output.err.println(sb.toString());
        }
    }

    public static void main(String[] args) {
        Output.out.setStream(System.out);
        Output.err.setStream(System.err);

        System.setOut(new PrintStream(new LoggerOutputStream() {
            @Override
            protected void log(String message) {
                Log.i("system.out", message);
            }
        }));
        System.setErr(new PrintStream(new LoggerOutputStream() {
            @Override
            protected void log(String message) {
                Log.e("system.err", message);
            }
        }));

        try {
            Main main = new Main();
            main.printLogo();
            main.internalMain(args);
        } catch (Throwable th) {
            Output.err.println(Log.getStackTraceString(th));
            System.exit(-1);
        }
    }

    private static abstract class LoggerOutputStream extends OutputStream {

        private static class Cache {
            int length = 0;
            byte[] data = new byte[4 * 1024];
        }

        private static final ThreadLocal<Cache> local = new ThreadLocal<Cache>() {
            @Override
            protected Cache initialValue() {
                return new Cache();
            }
        };

        @Override
        public void write(int b) {
            Cache cache = local.get();
            if (cache != null) {
                if (b != '\n') {
                    cache.data[cache.length++] = (byte) b;
                    if (cache.length < cache.data.length) {
                        return;
                    }
                }
                log(new String(cache.data, 0, cache.length));
                cache.length = 0;
            }
        }

        protected abstract void log(String message);
    }
}
