package android.tools;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameters;

import java.util.Map;

public class Plugin implements IPlugin {

    @Override
    public void init(JCommander.Builder builder) {
        builder.addCommand(new Command());
    }

    @Parameters(commandNames = "env")
    private static class Command implements ICommand {

        @Override
        public void run() throws Exception {
            Map<String, String> env = System.getenv();
            for (String key : env.keySet()) {
                Output.out.println(key + "=" + env.get(key));
            }
        }
    }
}
