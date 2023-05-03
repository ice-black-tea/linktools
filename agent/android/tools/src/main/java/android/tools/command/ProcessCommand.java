package android.tools.command;

import android.tools.Output;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

import org.ironman.framework.util.GsonUtil;
import org.ironman.framework.util.ProcessUtil;

@Parameters(commandNames = "process")
public class ProcessCommand extends Command {

    @Parameter(names = {"--list"}, order = 1, description = "List all processes")
    private boolean list = false;

    @Override
    public void run() {
        if (list) {
            Output.out.print(GsonUtil.toJson(ProcessUtil.getProcessList()));
        }
    }
}
