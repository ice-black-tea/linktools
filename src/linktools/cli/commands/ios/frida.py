#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : at_frida.py
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
from argparse import ArgumentParser
from typing import Optional

from linktools import logger, utils, environ, cli
from linktools.frida import FridaApplication, FridaShareScript, FridaScriptFile, FridaEvalCode
from linktools.frida.ios import IOSFridaServer


class Command(cli.IOSCommand):
    """
    Easy to use frida (require iOS device jailbreak)
    """

    def on_main_init(self):
        environ.show_log_time = True

    def add_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("-b", "--bundle-id", action="store", default=None,
                            help="target bundle id (default: frontmost application)")
        parser.add_argument("--spawn", action="store_true", default=False,
                            help="inject after spawn (default: false)")

        parser.add_argument("-P", "--parameters", metavar=("KEY", "VALUE"),
                            action="append", nargs=2, dest="user_parameters", default=[],
                            help="user script parameters")

        parser.add_argument("-l", "--load", metavar="SCRIPT",
                            action="append", dest="user_scripts", default=[],
                            type=lambda o: FridaScriptFile(o),
                            help="load user script")
        parser.add_argument("-e", "--eval", metavar="CODE", action="append", dest="user_scripts",
                            type=lambda o: FridaEvalCode(o),
                            help="evaluate code")
        parser.add_argument("-c", "--codeshare", metavar="URL", action="append", dest="user_scripts",
                            type=lambda o: FridaShareScript(o, cached=False),
                            help="load share script url")

        parser.add_argument("-a", "--auto-start", action="store_true", default=False,
                            help="automatically start when all processes exits")

    def run(self, args: [str]) -> Optional[int]:
        args = self.argument_parser.parse_args(args)
        device = args.parse_device()
        bundle_id = args.bundle_id

        user_parameters = {p[0]: p[1] for p in args.user_parameters}
        user_scripts = args.user_scripts
        for user_script in user_scripts:
            user_script.load()

        class Application(FridaApplication):

            def on_spawn_added(self, spawn):
                logger.debug(f"{spawn} added")
                if spawn.identifier != bundle_id:
                    try:
                        self.device.resume(spawn.pid)
                    except Exception as e:
                        logger.error(f"{e}")
                else:
                    self.load_script(spawn.pid, resume=True)

            def on_session_detached(self, session, reason, crash) -> None:
                logger.info(f"{session} detached, reason={reason}")
                if reason in ("connection-terminated", "device-lost"):
                    self.stop()
                elif len(self._sessions) == 0:
                    if args.auto_start:
                        app.load_script(app.device.spawn(bundle_id), resume=True)

        with IOSFridaServer(device=device, local_port=utils.pick_unused_port()) as server:

            app = Application(
                server,
                user_parameters=user_parameters,
                user_scripts=user_scripts,
                enable_spawn_gating=True
            )

            # 如果没有填包名，则找到顶层应用
            if utils.is_empty(bundle_id):
                target_app = app.device.get_frontmost_application()
                if target_app is None:
                    logger.error("Unknown frontmost application")
                    return
                bundle_id = target_app.identifier

            target_pids = set()

            if args.spawn:
                # 打开进程后注入
                app.load_script(app.device.spawn(bundle_id), resume=True)

            # 匹配正在运行的进程
            else:
                # 匹配所有app
                for target_app in app.device.enumerate_applications():
                    if target_app.pid > 0 and target_app.identifier == bundle_id:
                        target_pids.add(target_app.pid)

                # 匹配所有进程
                for target_process in app.device.enumerate_processes():
                    if target_process.pid > 0 and target_process.name == bundle_id:
                        target_pids.add(target_process.pid)

                if len(target_pids) > 0:
                    # 进程存在，直接注入
                    for pid in target_pids:
                        app.load_script(pid)
                elif args.auto_start:
                    # 进程不存在，打开进程后注入
                    app.load_script(app.device.spawn(bundle_id), resume=True)

            app.run()


command = Command()
if __name__ == "__main__":
    command.main()
