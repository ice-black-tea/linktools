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

from linktools import utils, logger
from linktools.android import AdbError, AndroidArgumentParser
from linktools.android.frida import FridaAndroidServer
from linktools.decorator import entry_point
from linktools.frida import FridaApplication, FridaShareScript


@entry_point(known_errors=[AdbError])
def main():
    parser = AndroidArgumentParser(description='easy to use frida')
    parser.add_argument('-p', '--package', action='store', default=None,
                        help='target package (default: current running package)')
    parser.add_argument('--spawn', action='store_true', default=False,
                        help='inject after spawn (default: false)')

    parser.add_argument("-P", "--parameters", help="user script parameters", metavar=("KEY", "VALUE"),
                        action='append', nargs=2, dest="user_parameters", default=[])
    parser.add_argument("-l", "--load", help="load user script", metavar="SCRIPT",
                        action='append', dest="user_scripts", default=[])
    parser.add_argument("-e", "--eval", help="evaluate code", metavar="CODE",
                        action='store', dest="eval_code", default=None)

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-c", "--codeshare", help="load share script url", metavar="URL",
                       action='store', dest="share_script_url", default=None)
    group.add_argument("-cc", "--codeshare-cached", help="load share script url, use cache first", metavar="URL",
                       action='store', dest="cached_share_script_url", default=None)

    parser.add_argument("-d", "--debug", action='store_true', default=False,
                        help="debug mode")

    args = parser.parse_args()
    device = args.parse_device()
    package = args.package

    user_parameters = {p[0]: p[1] for p in args.user_parameters}
    user_scripts = args.user_scripts
    eval_code = args.eval_code

    share_script = None
    if args.share_script_url is not None:
        share_script = FridaShareScript(args.share_script_url, cached=False)
    elif args.cached_share_script_url is not None:
        share_script = FridaShareScript(args.cached_share_script_url, cached=True)

    class Application(FridaApplication):

        def on_spawn_added(self, spawn):
            logger.debug(f"Spawn added: {spawn}", tag="[✔]")
            if device.extract_package(spawn.identifier) == package:
                self.load_script(spawn.pid, resume=True)
            else:
                self.resume(spawn.pid)

        def on_session_detached(self, session, reason, crash) -> None:
            logger.info(f"Detach process: {session.process_name} ({session.pid}), reason={reason}", tag="[*]")
            if reason in ("connection-terminated", "device-lost"):
                self.stop()
            elif len(self._sessions) == 0:
                app.load_script(app.device.spawn(package), resume=True)

    with FridaAndroidServer(device=device) as server:

        app = Application(
            server,
            debug=args.debug,
            user_parameters=user_parameters,
            user_scripts=user_scripts,
            eval_code=eval_code,
            share_script=share_script,
            enable_spawn_gating=True,
        )

        target_pids = set()

        if utils.is_empty(package):
            target_app = app.get_frontmost_application()
            if target_app is None:
                raise RuntimeError("unknown frontmost application")
            package = target_app.identifier

        if not args.spawn:
            # 匹配所有app
            for target_app in app.enumerate_applications():
                if target_app.pid not in target_pids:
                    if target_app.pid > 0 and target_app.identifier == package:
                        app.load_script(target_app.pid)
                        target_pids.add(target_app.pid)

            # 匹配所有进程
            for target_process in app.enumerate_processes():
                if target_process.pid > 0 and target_process.pid not in target_pids:
                    if device.extract_package(target_process.name) == package:
                        app.load_script(target_process.pid)
                        target_pids.add(target_process.pid)

        if len(target_pids) == 0:
            # 直接启动进程
            app.load_script(app.spawn(package), resume=True)

        app.run()


if __name__ == '__main__':
    main()
