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
import re
from argparse import ArgumentParser
from typing import Optional

from linktools import utils, environ
from linktools.cli.android import AndroidCommand
from linktools.frida import FridaApplication, FridaShareScript, FridaScriptFile, FridaEvalCode
from linktools.frida.android import AndroidFridaServer


class Command(AndroidCommand):
    """
    Easy to use frida (require Android device rooted)
    """
    def main(self, *args, **kwargs) -> None:
        environ.show_log_time = True
        environ.show_log_level = True
        return super().main(*args, **kwargs)

    def init_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("-p", "--package", action="store", default=None,
                            help="target package (default: frontmost application)")
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

        parser.add_argument("--redirect-address", metavar="ADDRESS", action="store", dest="redirect_address",
                            type=str,
                            help="redirect traffic to target address (default: localhost)")
        parser.add_argument("--redirect-port", metavar="PORT", action="store", dest="redirect_port",
                            type=utils.range_type(1, 65536),
                            help="redirect traffic to target port (default: 8080)")

        parser.add_argument("-a", "--auto-start", action="store_true", default=False,
                            help="automatically start when all processes exits")

    def run(self, args: [str]) -> Optional[int]:
        args = self.parse_args(args)
        device = args.parse_device()
        package = args.package

        user_parameters = {p[0]: p[1] for p in args.user_parameters}
        user_scripts = args.user_scripts

        class Application(FridaApplication):

            def on_session_detached(self, session, reason, crash) -> None:
                environ.logger.info(f"{session} detached, reason={reason}")
                if reason in ("connection-terminated", "device-lost"):
                    self.stop()
                elif len(self.sessions) == 0:
                    if args.auto_start:
                        app.load_script(app.device.spawn(package), resume=True)

        with AndroidFridaServer(device=device, local_port=utils.pick_unused_port()) as server:

            # 如果没有填包名，则找到顶层应用
            if utils.is_empty(package):
                target_app = server.get_frontmost_application()
                if target_app is None:
                    environ.logger.error("Unknown frontmost application")
                    return
                package = target_app.identifier

            app = Application(
                server,
                target_identifiers=rf"^{re.escape(package)}($|:)",
                user_parameters=user_parameters,
                user_scripts=user_scripts,
                enable_spawn_gating=True,
            )

            if args.spawn:
                # 打开进程后注入
                app.load_script(app.device.spawn(package), resume=True)

            elif app.inject_all():
                # 注入所有进程进程
                pass

            elif args.auto_start:
                # 进程不存在，打开进程后注入
                app.load_script(app.device.spawn(package), resume=True)

            if args.redirect_address or args.redirect_port:
                # 如果需要重定向到本地端口
                address = args.redirect_address
                port = args.redirect_port or 8080
                uid = device.get_uid(package)
                with device.redirect(address, port, uid):
                    app.run()
            else:
                app.run()


command = Command()
if __name__ == "__main__":
    command.main()
