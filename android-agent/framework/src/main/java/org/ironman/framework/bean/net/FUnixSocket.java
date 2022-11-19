package org.ironman.framework.bean.net;

/**
 * Created by hu on 19-2-13.
 */

public class FUnixSocket extends FSocket {
    public long refCnt;
    public String flags;
    public String type;
    public String path;
    public boolean readable;
    public boolean writable;
}
