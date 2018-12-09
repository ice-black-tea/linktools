#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : at_intent.py 
@time    : 2018/12/04
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
from android_tools import adb_device, utils

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='common intent action')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + android_tools.__version__)
    parser.add_argument('-s', '--serial', action='store', default=None,
                        help='use device with given serial')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--setting', dest='package', action='store_true',
                       help='start setting activity')
    group.add_argument('--setting-dev', dest='package', action='store_true',
                       help='start development setting activity')
    group.add_argument('--setting-dev2', dest='package', action='store_true',
                       help='start development setting activity')
    group.add_argument('--setting-app', dest='package', action='store', nargs='?', default="",
                       help='start application setting activity [default top-level package]')
    group.add_argument('--setting-cert', dest='path', action='store', default="",
                       help='start cert installer activity and install cert (need \'/data/local/tmp\' write permission)')
    group.add_argument('--browser', dest='url', action='store', default="",
                       help='start browser activity and jump to url (need scheme, such as https://antiy.cn)')

    args = parser.parse_args()
    device = adb_device(args.serial)

    if "--setting" in sys.argv:
        device.shell("am start -a android.settings.SETTINGS",
                     capture_output=False)
    elif "--setting-dev" in sys.argv:
        device.shell("am start -a android.intent.action.View "
                     "com.android.settings/com.android.settings.DevelopmentSettings",
                     capture_output=False)
    elif "--setting-dev2" in sys.argv:
        device.shell("am start -a android.settings.APPLICATION_DEVELOPMENT_SETTINGS",
                     capture_output=False)
    elif "--setting-app" in sys.argv:
        package = args.package if not utils.empty(args.package) else device.top_package()
        device.shell("am", "start", "-a", "android.settings.APPLICATION_DETAILS_SETTINGS",
                     "-d", "package:%s" % package,
                     capture_output=False)
    elif "--setting-cert" in sys.argv:
        path = "/data/local/tmp/%s/cert/%s" % (android_tools.__name__, utils.basename(args.path))
        device.exec("push", args.path, path, capture_output=False)
        device.shell("am", "start", "-n", "com.android.certinstaller/.CertInstallerMain",
                     "-a", "android.intent.action.VIEW", "-t", "application/x-x509-ca-cert",
                     "-d", "file://" + path,
                     capture_output = False)
    elif "--browser" in sys.argv:
        device.shell("am", "start", "-a", "android.intent.action.VIEW", "-d", args.url,
                     capture_output = False)
