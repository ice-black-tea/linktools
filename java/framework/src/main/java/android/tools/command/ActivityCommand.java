package android.tools.command;

import com.beust.jcommander.Parameters;

import org.ironman.framework.util.ActivityUtil;

@Parameters(commandNames = "activity")
public class ActivityCommand extends Command {

    @Override
    public void run() {
        ActivityUtil.startUsageAccessSettings();
    }
}
