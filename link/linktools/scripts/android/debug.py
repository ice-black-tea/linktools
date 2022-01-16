#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : at_debug.py
@time    : 2019/04/22
@site    :  
@software: PyCharm 

              ,----------------,              ,---------,
         ,-----------------------,          ,"        ,"|
       ,"                      ,"|        ,"        ,"  |
      +-----------------------+  |      ,"        ,"    |
      |  .-----------------.  |  |     +---------+      |
      |  |                 |  |  |     | -==----'|      |
      |  | $ sudo rm -rf / |  |  |     |         |      |
      |  |                 |  |  |/----|`---=    |      |
      |  |                 |  |  |   ,/|==== ooo |      ;
      |  |                 |  |  |  // |(((( [33]|    ,"
      |  `-----------------'  |," .;'| |((((     |  ,"
      +-----------------------+  ;;  | |         |,"
         /_)______________(_/  //'   | +---------+
    ___________________________/___  `,
   /  oooooooooooooooo  .o.  oooo /,   \,"-----------
  / ==ooooooooooooooo==.o.  ooo= //   ,`\--{)B     ,"
 /_==__==========__==_ooo__ooo=_/'   /___________,"
"""
from linktools import utils
from linktools.android import AdbError, AndroidArgumentParser
from linktools.decorator import entry_point


@entry_point(known_errors=[AdbError])
def main():
    parser = AndroidArgumentParser(description='debugger')
    parser.add_argument('package', action='store', default=None,
                        help='regular expression')
    parser.add_argument('activity', action='store', default=None,
                        help='regular expression')
    parser.add_argument('-p', '--port', action='store', type=int, default=8701,
                        help='fetch all apps')

    args = parser.parse_args()
    device = args.parse_device()

    device.shell("am", "force-stop", args.package, capture_output=False)
    device.shell("am", "start", "-D", "-n", "{}/{}".format(args.package, args.activity), capture_output=False)

    pid = utils.int(device.shell("top", "-n", "1", "|", "grep", args.package).split()[0])
    device.forward("tcp:{}".format(args.port), "jdwp:{}".format(pid), capture_output=False)

    data = input("jdb connect? [Y/n]: ").strip()
    if data in ["", "Y", "y"]:
        utils.exec("jdb", "-connect", "com.sun.jdi.SocketAttach:hostname=127.0.0.1,port={}".format(args.port),
                   capture_output=False)


if __name__ == '__main__':
    main()
