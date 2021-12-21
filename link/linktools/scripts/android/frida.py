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
import os

from linktools import utils, logger
from linktools.android import AdbError, AdbArgumentParser, Device
from linktools.decorator import entry_point
from linktools.frida import FridaApplication, FridaAndroidServer


@entry_point(known_errors=[AdbError])
def main():

    parser = AdbArgumentParser(description='easy to use frida')
    parser.add_argument('-p', '--package', action='store', default=None,
                        help='target package [default top-level package]')
    parser.add_argument('--spawn', action='store_true', default=False,
                        help='inject after spawn [default false]')
    parser.add_argument('--regular', action='store_true', default=False,
                        help="regular match package name")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-c", "--codeshare", help="load share script url", metavar="URL",
                       action='store', dest="share_script_url", default=None)
    group.add_argument("-cc", "--codeshare-cache", help="load share script url, use cache first", metavar="URL",
                       action='store', dest="cached_share_script_url", default=None)

    parser.add_argument("-l", "--load", help="load user script", metavar="SCRIPT",
                        action='store', dest="user_script", default=None)
    parser.add_argument("-e", "--eval", help="evaluate code", metavar="CODE",
                        action='store', dest="eval_code", default=None)
    parser.add_argument("-d", "--debug", action='store_true', default=False,
                        help="debug mode")

    args = parser.parse_args()

    device = Device(args.parse_adb_serial())
    package = args.package
    user_script = args.user_script
    eval_code = args.eval_code

    share_script_url = None
    share_script_cached = False
    if args.share_script_url is not None:
        share_script_url = args.share_script_url
        share_script_cached = False
    elif args.cached_share_script_url is not None:
        share_script_url = args.cached_share_script_url
        share_script_cached = True

    if utils.is_empty(package):
        package = device.get_top_package_name()
    if user_script is not None:
        user_script = os.path.abspath(os.path.expanduser(user_script))

    class ReloadFridaApplication(FridaApplication):

        def on_spawn_added(self, spawn):
            logger.debug(f"Spawn added: {spawn}", tag="[✔]")
            if device.extract_package_name(spawn.identifier) == package:
                self.load_script(spawn.pid, resume=True)
            else:
                self.resume(spawn.pid)

        def on_session_detached(self, session, reason) -> None:
            logger.info(f"Detach process: {session.process_name} ({session.pid}), reason={reason}", tag="[*]")
            if len(self._sessions) == 0:
                app.load_script(app.device.spawn(package), resume=True)

    with FridaAndroidServer(device_id=device.id) as server:

        app = ReloadFridaApplication(
            server,
            debug=args.debug,
            share_script_url=share_script_url,
            share_script_trusted=False,
            share_script_cached=share_script_cached,
            user_script=user_script,
            eval_code=eval_code,
            enable_spawn_gating=True
        )

        target_pids = set()

        if not args.spawn:

            # 匹配所有app
            for target_app in app.enumerate_applications():
                if target_app.pid not in target_pids:
                    if target_app.pid > 0 and target_app.identifier == package:
                        app.load_script(target_app.pid)
                        target_pids.add(target_app.pid)

            # 匹配所以进程
            for target_process in app.enumerate_processes():
                if target_process.pid > 0 and target_process.pid not in target_pids:
                    if device.extract_package_name(target_process.name) == package:
                        app.load_script(target_process.pid)
                        target_pids.add(target_process.pid)

        if len(target_pids) == 0:
            # 直接启动进程
            app.load_script(app.spawn(package), resume=True)

        app.run()


if __name__ == '__main__':
    main()
