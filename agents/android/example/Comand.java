package debug;

import android.tools.ICommand;

import com.beust.jcommander.Parameters;

@Parameters(commandNames = "debug")
public class Command implements ICommand {

    @Override
    public void run() throws Exception {
        throw new Exception("not implemented");
    }
}
