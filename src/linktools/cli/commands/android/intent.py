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
from argparse import ArgumentParser
from typing import Optional

from linktools import utils, logger, cli


class Command(cli.AndroidCommand):
    """
    Common intent actions
    """

    def add_arguments(self, parser: ArgumentParser) -> None:
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

    def run(self, args: [str]) -> Optional[int]:
        args = self.argument_parser.parse_args(args)
        device = args.parse_device()

        if "--setting" in sys.argv:
            device.shell("am", "start", "--user", "0",
                         "-a", "android.settings.SETTINGS",
                         log_output=True)
        elif "--setting-dev" in sys.argv:
            device.shell("am", "start", "--user", "0",
                         "-a", "android.settings.APPLICATION_DEVELOPMENT_SETTINGS",
                         log_output=True)
        elif "--setting-dev2" in sys.argv:
            device.shell("am", "start", "--user", "0",
                         "-a", "android.intent.action.View",
                         "com.android.settings/com.android.settings.DevelopmentSettings",
                         log_output=True)
        elif "--setting-app" in sys.argv:
            package = args.package if not utils.is_empty(args.package) else device.get_current_package()
            device.shell("am", "start", "--user", "0",
                         "-a", "android.settings.APPLICATION_DETAILS_SETTINGS",
                         "-d", "package:%s" % package,
                         log_output=True)
        elif "--setting-cert" in sys.argv:
            remote_path = device.get_data_path("cert", os.path.basename(args.path))
            device.push(args.path, remote_path,
                        log_output=True)
            device.shell("am", "start", "--user", "0",
                         "-n", "com.android.certinstaller/.CertInstallerMain",
                         "-a", "android.intent.action.VIEW",
                         "-t", "application/x-x509-ca-cert",
                         "-d", "file://%s" % remote_path,
                         log_output=True)
        elif "--install" in sys.argv:
            apk_path = args.path

            if args.path.startswith("http://") or args.path.startswith("https://"):
                logger.info(f"Download file: {args.path}")
                file = utils.UrlFile(args.path)
                apk_path = file.save()
                logger.info(f"Save file to local: {apk_path}")

            remote_path = device.get_data_path("apk", f"{int(time.time())}.apk")
            try:
                logger.info(f"Push file to remote: {remote_path}")
                device.push(apk_path, remote_path,
                            log_output=True)
                if device.uid >= 10000:
                    device.shell("am", "start", "--user", "0",
                                 "-a", "android.intent.action.VIEW",
                                 "-t", "application/vnd.android.package-archive",
                                 "-d", "file://%s" % remote_path,
                                 log_output=True)
                else:
                    device.shell("pm", "install", "--user", "0",
                                 "-r", "-t", "-d", "-f", remote_path,
                                 log_output=True)
            finally:
                logger.debug(f"Clear remote file: {remote_path}")
                device.shell("rm", remote_path, log_output=True)

        elif "--browser" in sys.argv:
            device.shell("am", "start", "--user", "0",
                         "-a", "android.intent.action.VIEW",
                         "-d", args.url,
                         log_output=True)

        return


command = Command()
if __name__ == "__main__":
    command.main()
