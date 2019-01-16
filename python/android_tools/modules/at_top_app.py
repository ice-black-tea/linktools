#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : at_top_app.py
@time    : 2018/11/25
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

import argparse
import datetime
import sys

import android_tools
from android_tools.adb import Device
from android_tools.utils import Utils

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='show top-level app\'s basic information')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + android_tools.__version__)
    parser.add_argument('-s', '--serial', action='store', default=None,
                        help='use device with given serial')

    group = parser.add_mutually_exclusive_group()
    group.add_argument('--package', action='store_const', const=True, default=False,
                       help='show top-level package name')
    group.add_argument('--activity', action='store_const', const=True, default=False,
                       help='show top-level activity name')
    group.add_argument('--path', action='store_const', const=True, default=False,
                       help='show top-level package path')
    group.add_argument('--kill', action='store_const', const=True, default=False,
                       help='kill top-level package')
    group.add_argument('--apk', dest='dest', action='store', type=str, nargs='?', default="",
                       help='pull top-level apk file')
    group.add_argument('--screen', dest='dest', action='store', type=str, nargs='?', default="",
                       help='capture screen and pull file')

    args = parser.parse_args()
    device = Device(args.serial)

    if args.package:
        print(device.get_top_package())
    elif args.activity:
        print(device.get_top_activity())
    elif args.path:
        print(device.get_apk_path(device.get_top_package()))
    elif args.kill:
        device.shell("am", "force-stop", device.get_top_package(), capture_output=False)
    elif "--apk" in sys.argv:
        package = device.get_top_package()
        path = device.get_save_path(package + ".apk")
        dest = args.dest if not Utils.is_empty(args.dest) else "."
        device.shell("cp", device.get_apk_path(package), path, capture_output=False)
        device.exec("pull", path, dest, capture_output=False)
        device.shell("rm", path)
    elif "--screen" in sys.argv:
        now = datetime.datetime.now()
        path = device.get_save_path("screenshot-" + now.strftime("%Y-%m-%d-%H-%M-%S") + ".png")
        dest = args.dest if not Utils.is_empty(args.dest) else "."
        device.shell("screencap", "-p", path, capture_output=False)
        device.exec("pull", path, dest, capture_output=False)
        device.shell("rm", path)
    else:
        print("package: ", device.get_top_package())
        print("activity:", device.get_top_activity())
        print("path:    ", device.get_apk_path(device.get_top_package()))
