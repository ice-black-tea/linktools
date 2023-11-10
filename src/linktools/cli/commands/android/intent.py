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
from argparse import ArgumentParser, Namespace
from typing import Optional

from linktools import utils
from linktools.android import Device
from linktools.cli import subcommand, subcommand_argument, AndroidCommand, SubCommandMixin


class Command(AndroidCommand, SubCommandMixin):
    """
    Common intent actions
    """

    def __init__(self):
        self.device: Optional[Device] = None

    def init_arguments(self, parser: ArgumentParser) -> None:
        self.add_subcommands(parser)

    def run(self, args: Namespace) -> Optional[int]:
        self.device = args.device_picker.pick()
        return self.run_subcommand(args)

    @subcommand("setting", help="start setting activity")
    def on_setting(self):
        self.device.shell("am", "start", "--user", "0",
                          "-a", "android.settings.SETTINGS",
                          log_output=True)

    @subcommand("setting-dev", help="start development setting activity")
    def on_setting_dev(self):
        self.device.shell("am", "start", "--user", "0",
                          "-a", "android.settings.APPLICATION_DEVELOPMENT_SETTINGS",
                          log_output=True)

    @subcommand("setting-dev2", help="start development setting activity")
    def on_setting_dev2(self):
        self.device.shell("am", "start", "--user", "0",
                          "-a", "android.intent.action.View",
                          "com.android.settings/com.android.settings.DevelopmentSettings",
                          log_output=True)

    @subcommand("setting-app", help="start application setting activity (default: current running package)")
    @subcommand_argument("package")
    def on_setting_app(self, package: str = None):
        package = package if not utils.is_empty(package) else self.device.get_current_package()
        self.device.shell("am", "start", "--user", "0",
                          "-a", "android.settings.APPLICATION_DETAILS_SETTINGS",
                          "-d", "package:%s" % package,
                          log_output=True)

    @subcommand("setting-cert", help="install cert (need \'/data/local/tmp\' write permission)")
    @subcommand_argument("path")
    def on_setting_cert(self, path: str):
        remote_path = self.device.get_data_path("cert", os.path.basename(path))
        self.device.push(path, remote_path, log_output=True)
        self.device.shell("am", "start", "--user", "0",
                          "-n", "com.android.certinstaller/.CertInstallerMain",
                          "-a", "android.intent.action.VIEW",
                          "-t", "application/x-x509-ca-cert",
                          "-d", "file://%s" % remote_path,
                          log_output=True)

    @subcommand("install", help="install apk file (need \'/data/local/tmp\' write permission)")
    @subcommand_argument("path")
    def on_install(self, path: str):
        self.device.install(path,
                            opts=["-r", "-t", "-d", "-f"],
                            log_output=True)

    @subcommand("browser", help="start browser activity and jump to url")
    @subcommand_argument("url", help="e.g. https://antiy.cn")
    def on_browser(self, url: str):
        self.device.shell("am", "start", "--user", "0",
                          "-a", "android.intent.action.VIEW",
                          "-d", url,
                          log_output=True)


command = Command()
if __name__ == "__main__":
    command.main()
