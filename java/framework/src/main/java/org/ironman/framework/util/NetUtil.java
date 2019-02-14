package org.ironman.framework.util;

import android.text.TextUtils;

import org.ironman.framework.Const;
import org.ironman.framework.bean.net.JUnixSocket;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by hu on 19-2-13.
 */

public class NetUtil {

    private static final String PROC_NET_TCP = "/proc/net/tcp";
    private static final String PROC_NET_TCP6 = "/proc/net/tcp6";
    private static final String PROC_NET_UDP = "/proc/net/udp";
    private static final String PROC_NET_UDP6 = "/proc/net/udp6";
    private static final String PROC_NET_RAW = "/proc/net/raw";
    private static final String PROC_NET_RAW6 = "/proc/net/raw6";
    private static final String PROC_NET_UNIX = "/proc/net/unix";

    public static List<JUnixSocket> getUnixSockets() throws IOException {
        List<JUnixSocket> sockets = new ArrayList<>();
        String result = FileUtil.readFile(PROC_NET_UNIX);
        String[] items = result.split(Const.LINE_BREAK);
        for (int i = 1; i < items.length; i++) {
            String[] detail = items[i].split(Const.COMMON_SEPARATOR);
            if (detail.length < 6) {
                continue;
            }

            long num = CommonUtil.parseLong(detail[0], 16, 0);
            long refCount = CommonUtil.parseLong(detail[1], 16, 0);
            long protocol = CommonUtil.parseLong(detail[2], 16, 0);
            long flags = CommonUtil.parseLong(detail[3], 16, 0);
            int type = CommonUtil.parseInt(detail[4], 16, 0);
            int state = CommonUtil.parseInt(detail[5], 16, 0);
            long inode = CommonUtil.parseLong(detail[6], 0);
            String path = detail.length > 7 ? detail[7] : null;
            int pid = detail.length > 8 ? CommonUtil.parseInt(detail[8], 16, 0) : 0;

            JUnixSocket socket = new JUnixSocket();
            switch ((int)protocol) {
                case 0:
                    socket.proto = "unix";
                    break;
                default:
                    socket.proto = "";
            }

            switch (type) {
                case Const.SOCK_STREAM:
                    socket.type = "STREAM";
                    break;
                case Const.SOCK_DGRAM:
                    socket.type = "DGRAM";
                    break;
                case Const.SOCK_RAW:
                    socket.type = "RAW";
                    break;
                case Const.SOCK_RDM:
                    socket.type = "RDM";
                    break;
                case Const.SOCK_SEQPACKET:
                    socket.type = "SEQPACKET";
                    break;
                default:
                    socket.type = "UNKNOWN";
            }

            switch (state) {
                case Const.SS_FREE:
                    socket.state = "FREE";
                    break;
                case Const.SS_UNCONNECTED:
                    /*
                     * Unconnected sockets may be listening
                     * for something.
                     */
                    if ((flags & Const.SO_ACCEPTCON) != 0) {
                        socket.state = "LISTENING";
                    } else {
                        socket.state = "";
                    }
                    break;
                case Const.SS_CONNECTING:
                    socket.state = "CONNECTING";
                    break;
                case Const.SS_CONNECTED:
                    socket.state = "CONNECTED";
                    break;
                case Const.SS_DISCONNECTING:
                    socket.state = "DISCONNECTING";
                    break;
                default:
                    socket.state = "UNKNOWN";
            }

            socket.flags = "[ ";
            if ((flags & Const.SO_ACCEPTCON) != 0)
                socket.flags = socket.flags.concat("ACC ");
            if ((flags & Const.SO_WAITDATA) != 0)
                socket.flags = socket.flags.concat("W ");
            if ((flags & Const.SO_NOSPACE) != 0)
                socket.flags = socket.flags.concat("N ");
            socket.flags = socket.flags.concat("]");

            socket.refCnt = refCount;
            socket.inode = inode;
            socket.pid = pid;

            if (!TextUtils.isEmpty(path)) {
                socket.path = path;
                socket.readable = FileUtil.canRead(path);
                socket.writable = FileUtil.canWrite(path);
            }

            sockets.add(socket);
        }
        return sockets;
    }

}
