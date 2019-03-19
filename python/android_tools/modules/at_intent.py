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
from android_tools.adb import Device, AdbError
from android_tools.argparser import AdbArgumentParser
from android_tools.utils import Utils


def main():
    parser = AdbArgumentParser(description='common intent action')

    group = parser.add_argument_group(title="common arguments")
    _group = group.add_mutually_exclusive_group(required=True)
    _group.add_argument('--setting', dest='package', action='store_true',
                        help='start setting activity')
    _group.add_argument('--setting-dev', dest='package', action='store_true',
                        help='start development setting activity')
    _group.add_argument('--setting-dev2', dest='package', action='store_true',
                        help='start development setting activity')
    _group.add_argument('--setting-app', dest='package', action='store', nargs='?', default="",
                        help='start application setting activity [default top-level package]')
    _group.add_argument('--setting-cert', dest='path', action='store', default="",
                        help='install cert (need \'/data/local/tmp\' write permission)')
    _group.add_argument('--install', dest='path', action='store', default="",
                        help='install apk file')
    _group.add_argument('--browser', dest='url', action='store', default="",
                        help='start browser activity and jump to url (need scheme, such as https://antiy.cn)')

    adb, args = parser.parse_adb_args()
    args = parser.parse_args(args)
    device = Device(adb.extend())

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
        package = args.package if not Utils.is_empty(args.package) else device.get_top_package()
        device.shell("am", "start", "--user", "0",
                     "-a", "android.settings.APPLICATION_DETAILS_SETTINGS",
                     "-d", "package:%s" % package,
                     capture_output=False)
    elif "--setting-cert" in sys.argv:
        path = "/data/local/tmp/%s/cert/%s" % (android_tools.__name__, Utils.basename(args.path))
        device.exec("push", args.path, path, capture_output=False)
        device.shell("am", "start", "--user", "0",
                     "-n", "com.android.certinstaller/.CertInstallerMain",
                     "-a", "android.intent.action.VIEW",
                     "-t", "application/x-x509-ca-cert",
                     "-d", "file://%s" % path,
                     capture_output=False)
    elif "--install" in sys.argv:
        path = device.get_save_path(Utils.basename(args.path))
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
    except KeyboardInterrupt:
        pass
    except AdbError as e:
        print(e)
