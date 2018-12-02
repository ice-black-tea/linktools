package android.tools.command;

import com.beust.jcommander.Parameter;

public class CommandMain {

    @Parameter(names = { "-h", "--help" }, help = true, description = "Show this help message and exit")
    public boolean help;

}
