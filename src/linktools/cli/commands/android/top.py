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
   /  oooooooooooooooo  .o.  oooo /,   `,"-----------
  / ==ooooooooooooooo==.o.  ooo= //   ,``--{)B     ,"
 /_==__==========__==_ooo__ooo=_/'   /___________,"
"""

import datetime
import sys
from argparse import ArgumentParser, Namespace
from typing import Optional

from linktools import utils, environ
from linktools.cli import AndroidCommand


class Command(AndroidCommand):
    """
    Fetch current running app's basic information
    """

    def init_arguments(self, parser: ArgumentParser) -> None:
        group = parser.add_mutually_exclusive_group()
        group.add_argument('-p', '--package', action='store_const', const=True, default=False,
                           help='show current package name')
        group.add_argument('-a', '--activity', action='store_const', const=True, default=False,
                           help='show current activity name')
        group.add_argument('--path', action='store_const', const=True, default=False,
                           help='show current apk path')
        group.add_argument('--kill', action='store_const', const=True, default=False,
                           help='kill current package')
        group.add_argument('--apk', metavar='DEST', action='store', type=str, nargs='?', default=".",
                           help='pull current apk file')
        group.add_argument('--screen', metavar='DEST', action='store', type=str, nargs='?', default=".",
                           help='capture screen and pull file')

    def run(self, args: Namespace) -> Optional[int]:
        device = args.device_picker.pick()

        if args.package:
            print(device.get_current_package())
        elif args.activity:
            print(device.get_current_activity())
        elif args.path:
            print(device.get_apk_path(device.get_current_package()))
        elif args.kill:
            device.shell("am", "force-stop", device.get_current_package(), log_output=True)
        elif "--apk" in sys.argv:
            name = device.get_current_package()
            environ.logger.info(f"Find current package: {name}")
            app = device.get_app(name)
            environ.logger.info(f"Find current apk path: {app.source_dir}")
            path = device.get_storage_path("{}_{}.apk".format(app.name, app.version_name))
            dest = args.apk if not utils.is_empty(args.apk) else "."
            device.shell("mkdir", "-p", device.get_storage_path(), log_output=True)
            device.shell("cp", app.source_dir, path, log_output=True)
            device.pull(path, dest, log_output=True)
            device.shell("rm", path)
        elif "--screen" in sys.argv:
            now = datetime.datetime.now()
            path = device.get_storage_path("screenshot-" + now.strftime("%Y-%m-%d-%H-%M-%S") + ".png")
            dest = args.screen if not utils.is_empty(args.screen) else "."
            device.shell("mkdir", "-p", device.get_storage_path(), log_output=True)
            device.shell("screencap", "-p", path, log_output=True)
            device.pull(path, dest, log_output=True)
            device.shell("rm", path)
        else:
            app = device.get_current_package()
            environ.logger.info(f"Package:  {app}")
            environ.logger.info(f"Activity: {device.get_current_activity()}")
            environ.logger.info(f"Path:     {device.get_apk_path(app)}")

        return


command = Command()
if __name__ == "__main__":
    command.main()
