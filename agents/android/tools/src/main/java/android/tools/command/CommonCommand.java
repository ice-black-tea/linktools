package android.tools.command;

import android.app.Application;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.pm.PackageInfo;
import android.text.TextUtils;
import android.tools.ICommand;
import android.tools.Output;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.Parameters;

import org.ironman.framework.Environment;
import org.ironman.framework.util.ActivityUtil;
import org.ironman.framework.util.GsonUtil;
import org.ironman.framework.util.NetworkUtil;
import org.ironman.framework.util.PackageUtil;
import org.ironman.framework.util.ProcessUtil;

import java.util.List;

@Parameters(commandNames = "common")
public class CommonCommand implements ICommand {

    @Parameter(names = {"--process"}, order = 0, description = "List all processes")
    private boolean process = false;

    @Parameter(names = {"--tcp-sock"}, order = 1, description = "List all tcp sockets")
    private boolean tcp_sock = false;

    @Parameter(names = {"--udp-sock"}, order = 2, description = "List all udp sockets")
    private boolean udp_sock = false;

    @Parameter(names = {"--raw-sock"}, order = 3, description = "List all raw sockets")
    private boolean raw_sock = false;

    @Parameter(names = {"--unix-sock"}, order = 4, description = "List all unix sockets")
    private boolean unix_sock = false;

    @Parameter(names = {"--top-package"}, order = 100, description = "Display top-level package")
    private boolean top_package = false;

    @Parameter(names = {"--top-activity"}, order = 102, description = "Display top-level activity")
    private boolean top_activity = false;

    @Parameter(names = {"--apk-file"}, order = 103, description = "Display package file")
    private String apk_file = null;

    @Parameter(names = {"--set-clipboard"}, order = 104, description = "Set clipboard content")
    private String set_clipboard = null;

    @Parameter(names = {"--usage-access"}, order = 200, description = "Start usage access settings")
    private boolean usage_access = false;

    @Override
    public void run() throws Exception {
        if (process) {
            Output.out.print(GsonUtil.toJson(ProcessUtil.getProcessList()));
        } else if (top_package) {
            String packageName = PackageUtil.getTopPackage();
            if (!TextUtils.isEmpty(packageName)) {
                Output.out.print(packageName);
            }
        } else if (top_activity) {
            String activityName = ActivityUtil.getTopActivity();
            if (!TextUtils.isEmpty(activityName)) {
                Output.out.print(activityName);
            }
        } else if (!TextUtils.isEmpty(apk_file)) {
            List<PackageInfo> packages = PackageUtil.getPackages(apk_file);
            if (!packages.isEmpty()) {
                Output.out.print(packages.get(0).applicationInfo.publicSourceDir);
            }
        } else if (!TextUtils.isEmpty(set_clipboard)) {
            Application app = Environment.getApplication();
            ClipboardManager cm = (ClipboardManager) app.getSystemService(Context.CLIPBOARD_SERVICE);
            cm.setPrimaryClip(ClipData.newPlainText("text", set_clipboard));
        } else if (tcp_sock) {
            Output.out.print(GsonUtil.toJson(NetworkUtil.getTcpSockets()));
        } else if (udp_sock) {
            Output.out.print(GsonUtil.toJson(NetworkUtil.getUdpSockets()));
        } else if (raw_sock) {
            Output.out.print(GsonUtil.toJson(NetworkUtil.getRawSockets()));
        } else if (unix_sock) {
            Output.out.print(GsonUtil.toJson(NetworkUtil.getUnixSockets()));
        } else if (usage_access) {
            ActivityUtil.startUsageAccessSettings();
        }
    }
}
