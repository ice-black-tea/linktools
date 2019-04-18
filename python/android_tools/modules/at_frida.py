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
import hashlib
import sys

from frida import ServerNotRunningError
from watchdog.events import *
from watchdog.observers import Observer

from android_tools.adb import AdbError
from android_tools.argparser import AdbArgumentParser
from android_tools.frida import FridaHelper
from android_tools.utils import Utils


class FridaScript(object):

    def __init__(self, path: str, helper: FridaHelper, name: str, restart: bool):
        self.helper = helper
        self.name = name
        self.path = path
        self.restart = restart
        self._md5 = ""

    def load(self):
        with open(self.path, "r") as fd:
            jscode = fd.read()
        # check md5
        md5 = hashlib.md5(jscode.encode("utf-8")).hexdigest()
        if self._md5 == md5:
            return
        self._md5 = md5
        self.helper.log("*", "Loading script: %s" % self.path)
        self.helper.detach_sessions()
        self.helper.run_script(self.name, jscode, restart=self.restart)


class FridaEventHandler(FileSystemEventHandler):

    def __init__(self, script: FridaScript):
        FileSystemEventHandler.__init__(self)
        self.script = script

    def on_moved(self, event):
        if event.dest_path == self.script.path:
            self.script.load()

    def on_created(self, event):
        if event.src_path == self.script.path:
            self.script.load()

    def on_deleted(self, event):
        pass

    def on_modified(self, event):
        if event.src_path == self.script.path:
            self.script.load()


def main():
    parser = AdbArgumentParser(description='easy to use frida')

    group = parser.add_argument_group(title="common arguments")
    group.add_argument('-p', '--package', action='store', default=None,
                       help='target package [default top-level package]')
    _group = group.add_mutually_exclusive_group(required=True)
    _group.add_argument('-f', '--file', action='store', type=str, default=None,
                        help='javascript file')
    _group.add_argument('--code', action='store', type=str, default=None,
                        help='javascript code')
    group.add_argument('-r', '--restart', action='store_true', default=False,
                       help='inject after restart [default false]')

    args = parser.parse_args()
    helper = FridaHelper(device_id=args.parse_adb_serial())

    package = args.package
    if Utils.is_empty(package):
        package = helper.device.get_top_package()
    restart = args.restart

    if "-f" in sys.argv or "--file" in sys.argv:
        observer = Observer()
        path = Utils.abspath(args.file)
        script = FridaScript(path, helper, package, restart)
        event_handler = FridaEventHandler(script)
        observer.schedule(event_handler, os.path.dirname(path))
        observer.start()
        script.load()
    elif "-c" in sys.argv or "--code" in sys.argv:
        helper.run_script(package, args.code, restart=restart)

    sys.stdin.read()


if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt, EOFError, AdbError, ServerNotRunningError) as e:
        print(e)
