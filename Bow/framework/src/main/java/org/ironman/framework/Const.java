package org.ironman.framework;

/**
 * Created by hu on 19-2-13.
 */

public class Const {

    public static final String LINE_BREAK = "\n";
    public static final String COMMON_SEPARATOR = "[\\s\\x00]+";
    
    public static final int NETSTAT_CONNECTED = 0x01;
    public static final int NETSTAT_LISTENING = 0x02;
    public static final int NETSTAT_NUMERIC   = 0x04;
    public static final int NETSTAT_TCP       = 0x10;
    public static final int NETSTAT_UDP       = 0x20;
    public static final int NETSTAT_RAW       = 0x40;
    public static final int NETSTAT_UNIX      = 0x80;
    public static final int NETSTAT_ALLPROTO  = (NETSTAT_TCP|NETSTAT_UDP|NETSTAT_RAW|NETSTAT_UNIX);

    public static final int SOCK_DGRAM        = 1;
    public static final int SOCK_STREAM       = 2;
    public static final int SOCK_RAW          = 3;
    public static final int SOCK_RDM          = 4;
    public static final int SOCK_SEQPACKET    = 5;
    public static final int SOCK_DCCP         = 6;
    public static final int SOCK_PACKET       = 10;

    public static final int SS_FREE           = 0;         /* not allocated                */
    public static final int SS_UNCONNECTED    = 1;         /* unconnected to any socket    */
    public static final int SS_CONNECTING     = 2;         /* in process of connecting     */
    public static final int SS_CONNECTED      = 3;         /* connected to socket          */
    public static final int SS_DISCONNECTING  = 4;         /* in process of disconnecting  */

    public static final int SO_ACCEPTCON      = (1<<16);   /* performed a listen           */
    public static final int SO_WAITDATA       = (1<<17);   /* wait data to read            */
    public static final int SO_NOSPACE        = (1<<18);   /* no space to write            */
}
