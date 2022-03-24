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
import os
import sys
import time

import linktools
from linktools import utils, resource
from linktools.android import AdbError, AndroidArgumentParser
from linktools.decorator import entry_point


@entry_point(known_errors=[AdbError])
def main():
    parser = AndroidArgumentParser(description='common intent action')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--setting', dest='package', action='store_true',
                       help='start setting activity')
    group.add_argument('--setting-dev', dest='package', action='store_true',
                       help='start development setting activity')
    group.add_argument('--setting-dev2', dest='package', action='store_true',
                       help='start development setting activity')
    group.add_argument('--setting-app', dest='package', action='store', nargs='?', default="",
                       help='start application setting activity (default: current running package)')
    group.add_argument('--setting-cert', dest='path', action='store', default="",
                       help='install cert (need \'/data/local/tmp\' write permission)')
    group.add_argument('--install', dest='path', action='store', default="",
                       help='install apk file (need \'/data/local/tmp\' write permission)')
    group.add_argument('--browser', dest='url', action='store', default="",
                       help='start browser activity and jump to url (need scheme, such as https://antiy.cn)')

    args = parser.parse_args()
    device = args.parse_device()

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
        package = args.package if not utils.is_empty(args.package) else device.get_current_package()
        device.shell("am", "start", "--user", "0",
                     "-a", "android.settings.APPLICATION_DETAILS_SETTINGS",
                     "-d", "package:%s" % package,
                     capture_output=False)
    elif "--setting-cert" in sys.argv:
        path = "/data/local/tmp/%s/cert/%s" % (linktools.__name__, os.path.basename(args.path))
        device.push(args.path, path, capture_output=False)
        device.shell("am", "start", "--user", "0",
                     "-n", "com.android.certinstaller/.CertInstallerMain",
                     "-a", "android.intent.action.VIEW",
                     "-t", "application/x-x509-ca-cert",
                     "-d", "file://%s" % path,
                     capture_output=False)
    elif "--install" in sys.argv:
        apk_path = args.path
        if args.path.startswith("http://") or args.path.startswith("https://"):
            url = args.path
            apk_path = resource.get_temp_path(
                "download",
                utils.get_md5(url),
                utils.guess_file_name(url)
            )
            utils.download(url, apk_path)
        path = "/data/local/tmp/%s/apk/%s.apk" % (linktools.__name__, int(time.time()))
        device.push(apk_path, path, capture_output=False)
        # device.shell("am", "start", "--user", "0",
        #              "-a", "android.intent.action.VIEW",
        #              "-t", "application/vnd.android.package-archive",
        #              "-d", "file://%s" % path,
        #              capture_output=False)
        device.shell("pm", "install", "--user", "0",
                     "-r", "-t", "-d", "-f", path,
                     capture_output=False)
        device.shell("rm", path, capture_output=False)
    elif "--browser" in sys.argv:
        device.shell("am", "start", "--user", "0",
                     "-a", "android.intent.action.VIEW",
                     "-d", args.url,
                     capture_output=False)


if __name__ == '__main__':
    main()
