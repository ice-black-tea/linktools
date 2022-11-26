package android.tools.command;

import android.tools.Output;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

import org.ironman.framework.util.GsonUtil;
import org.ironman.framework.util.NetworkUtil;

@Parameters(commandNames = "network")
public class NetworkCommand extends Command {

    @Parameter(names = {"--tcp-sock"}, order = 3, description = "Display tcp sockets")
    private boolean tcp_sock = false;

    @Parameter(names = {"--udp-sock"}, order = 3, description = "Display udp sockets")
    private boolean udp_sock = false;

    @Parameter(names = {"--raw-sock"}, order = 3, description = "Display raw sockets")
    private boolean raw_sock = false;

    @Parameter(names = {"--unix-sock"}, order = 3, description = "Display unix sockets")
    private boolean unix_sock = false;

    @Override
    public void run() throws Exception {
        if (tcp_sock) {
            Output.out.print(GsonUtil.toJson(NetworkUtil.getTcpSockets()));
        } else if (udp_sock) {
            Output.out.print(GsonUtil.toJson(NetworkUtil.getUdpSockets()));
        } else if (raw_sock) {
            Output.out.print(GsonUtil.toJson(NetworkUtil.getRawSockets()));
        } else if (unix_sock) {
            Output.out.print(GsonUtil.toJson(NetworkUtil.getUnixSockets()));
        }
    }
}
