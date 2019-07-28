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
import sys

import android_tools

from android_tools import utils
from android_tools.adb import Device, AdbError
from android_tools.argparser import AdbArgumentParser


def main():
    parser = AdbArgumentParser(description='common intent action')

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
                       help='install cert (need \'/data/local/tmp\' write permission)')
    group.add_argument('--install', dest='path', action='store', default="",
                       help='install apk file')
    group.add_argument('--browser', dest='url', action='store', default="",
                       help='start browser activity and jump to url (need scheme, such as https://antiy.cn)')

    args = parser.parse_args()
    device = Device(args.parse_adb_serial())

    if "--setting" in sys.argv:
        device.shell("am", "start", "--user", "0",
                     "-a", "android.settings.SETTINGS",
                     capture_output=False)
    elif "--setting-dev" in sys.argv:
        device.shell("am", "start", "--user", "0",
                     "-a", "android.settings.APPLICATION_DEVELOPMENT_SETTINGS",
                     capture_output=False)
    elif "--setting-dev2" in sys.argv:
        device.shell("am", "start", "--user", "0",
                     "-a", "android.intent.action.View",
                     "com.android.settings/com.android.settings.DevelopmentSettings",
                     capture_output=False)
    elif "--setting-app" in sys.argv:
        package = args.package if not utils.is_empty(args.package) else device.get_top_package()
        device.shell("am", "start", "--user", "0",
                     "-a", "android.settings.APPLICATION_DETAILS_SETTINGS",
                     "-d", "package:%s" % package,
                     capture_output=False)
    elif "--setting-cert" in sys.argv:
        path = "/data/local/tmp/%s/cert/%s" % (android_tools.__name__, utils.basename(args.path))
        device.exec("push", args.path, path, capture_output=False)
        device.shell("am", "start", "--user", "0",
                     "-n", "com.android.certinstaller/.CertInstallerMain",
                     "-a", "android.intent.action.VIEW",
                     "-t", "application/x-x509-ca-cert",
                     "-d", "file://%s" % path,
                     capture_output=False)
    elif "--install" in sys.argv:
        path = device.get_storage_path(utils.basename(args.path))
        device.exec("push", args.path, path, capture_output=False)
        device.shell("am", "start", "--user", "0",
                     "-a", "android.intent.action.VIEW",
                     "-t", "application/vnd.android.package-archive",
                     "-d", "file://%s" % path,
                     capture_output=False)
    elif "--browser" in sys.argv:
        device.shell("am", "start", "--user", "0",
                     "-a", "android.intent.action.VIEW",
                     "-d", args.url,
                     capture_output=False)


if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt, EOFError, AdbError) as e:
        print(e)
