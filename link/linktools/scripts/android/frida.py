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

from linktools import utils, logger, range_type
from linktools.android import AdbError, AndroidArgumentParser
from linktools.android.frida import FridaAndroidServer
from linktools.decorator import entry_point
from linktools.frida import FridaApplication, FridaShareScript, FridaScriptFile, FridaEvalCode


@entry_point(known_errors=[AdbError])
def main():
    parser = AndroidArgumentParser(description="easy to use frida")
    parser.add_argument("-p", "--package", action="store", default=None,
                        help="target package (default: current running package)")
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
    parser.add_argument("--redirect-port", metavar="ADDRESS", action="store", dest="redirect_port",
                        type=range_type(1, 65536),
                        help="redirect traffic to target port (default: 8080)")

    parser.add_argument("-a", "--auto-start", action="store_true", default=False,
                        help="automatically start when all processes exits")
    parser.add_argument("-d", "--debug", action="store_true", default=False,
                        help="enable debug mode")

    args = parser.parse_args()
    device = args.parse_device()
    package = args.package

    user_parameters = {p[0]: p[1] for p in args.user_parameters}
    user_scripts = args.user_scripts

    class Application(FridaApplication):

        def on_spawn_added(self, spawn):
            logger.debug(f"Spawn added: {spawn}")
            if device.extract_package(spawn.identifier) == package:
                self.load_script(spawn.pid, resume=True)
            else:
                self.resume(spawn.pid)

        def on_session_detached(self, session, reason, crash) -> None:
            logger.info(f"Detach process: {session.process_name} ({session.pid}), reason={reason}")
            if reason in ("connection-terminated", "device-lost"):
                self.stop()
            elif len(self._sessions) == 0:
                if args.auto_start:
                    app.load_script(app.device.spawn(package), resume=True)

    with FridaAndroidServer(device=device) as server:

        app = Application(
            server,
            debug=args.debug,
            user_parameters=user_parameters,
            user_scripts=user_scripts,
            enable_spawn_gating=True,
        )

        # 如果没有填包名，则找到顶层应用
        if utils.is_empty(package):
            target_app = app.get_frontmost_application()
            if target_app is None:
                logger.error("Unknown frontmost application")
                return
            package = target_app.identifier

        target_pids = set()

        if args.spawn:
            # 打开进程后注入
            app.load_script(app.spawn(package), resume=True)

        else:
            # 匹配所有app
            for target_app in app.enumerate_applications():
                if target_app.pid > 0 and target_app.identifier == package:
                    target_pids.add(target_app.pid)

            # 匹配所有进程
            for target_process in app.enumerate_processes():
                if target_process.pid > 0 and device.extract_package(target_process.name) == package:
                    target_pids.add(target_process.pid)

            if len(target_pids) > 0:
                # 进程存在，直接注入
                for pid in target_pids:
                    app.load_script(pid)
            elif args.auto_start:
                # 进程不存在，打开进程后注入
                app.load_script(app.spawn(package), resume=True)

        if args.redirect_address or args.redirect_port:
            # 如果需要重定向到本地端口
            with device.redirect(args.redirect_address, args.redirect_port or 8080):
                app.run()
        else:
            app.run()


if __name__ == '__main__':
    main()
