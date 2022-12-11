#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Datetime  : 2022/12/8 17:05
# Author    : HuJi <jihu.hj@alibaba-inc.com>

from linktools import utils
from linktools.argparser.ios import IOSArgumentParser
from linktools.decorator import entry_point
from linktools.ios import MuxError, Device


@entry_point(known_errors=(MuxError,))
def main():
    remote_path_prefix = "@"

    parser = IOSArgumentParser(description="OpenSSH secure file copy (iOS device need jailbreak)")

    parser.add_argument("-u", "--user", action="store", default="root",
                        help="iOS ssh user (default: root)")
    parser.add_argument("-p", "--port", action="store", type=int, default=22,
                        help="iOS ssh port (default: 22)")
    parser.add_argument("-l", "--local-port", action="store", type=int, default=2222,
                        help="local listening port (default: 2222)")
    parser.add_argument("scp_args", nargs="...",
                        help=f"scp args, remote path needs to be prefixed with \"{remote_path_prefix}\"")

    args = parser.parse_args()
    device: Device = args.parse_device()

    scp_args = []
    for arg in args.scp_args:
        if arg.startswith(remote_path_prefix):
            arg = f"{args.user}@127.0.0.1:{arg[len(remote_path_prefix):]}"
        scp_args.append(arg)

    with device.forward(args.local_port, args.port):
        scp_args = [
            "scp", "-P", args.local_port,
            *scp_args
        ]
        return utils.Popen(*scp_args).call()


if __name__ == '__main__':
    main()
