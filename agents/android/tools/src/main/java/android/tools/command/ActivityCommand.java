package android.tools.command;

import android.tools.ICommand;

import com.beust.jcommander.Parameters;

import org.ironman.framework.util.ActivityUtil;

@Parameters(commandNames = "activity")
public class ActivityCommand implements ICommand {

    @Override
    public void run() {
        ActivityUtil.startUsageAccessSettings();
    }
}
