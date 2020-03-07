#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : ATFrida.py
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

try:
    # noinspection PyPackageRequirements
    from frida import ServerNotRunningError
except:
    print("please use the following command to install frida first:", sys.executable, "-m", "pip", "install", "frida")
    exit(1)

from watchdog.events import *
from watchdog.observers import Observer

from linktools import utils
from linktools.android import AdbError, AdbArgumentParser
from linktools.android.frida import FridaHelper


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
    parser.add_argument('-p', '--package', action='store', default=None,
                        help='target package [default top-level package]')
    parser.add_argument('-r', '--restart', action='store_true', default=False,
                        help='inject after restart [default false]')
    parser.add_argument('file', action='store', default=None,
                        help='javascript file')

    args = parser.parse_args()
    helper = FridaHelper(device_id=args.parse_adb_serial())

    package = args.package
    if utils.is_empty(package):
        package = helper.device.get_top_package_name()
    restart = args.restart

    observer = Observer()
    path = utils.abspath(args.file)
    script = FridaScript(path, helper, package, restart)
    event_handler = FridaEventHandler(script)
    observer.schedule(event_handler, os.path.dirname(path))
    observer.start()
    script.load()

    sys.stdin.read()


if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt, EOFError, FileNotFoundError) as e:
        print(e)
    except (AdbError, ServerNotRunningError) as e:
        print(e)
