package debug;

import android.tools.command.Command;

import com.beust.jcommander.Parameters;

@Parameters(commandNames = "empty")
public class EmptyCommand extends Command {

    @Override
    public void run() throws Exception {
        throw new Exception("not implemented");
    }
}