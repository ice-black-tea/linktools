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
import argparse
import hashlib
import sys

import android_tools
from watchdog.events import *
from watchdog.observers import Observer

from android_tools import frida_helper, utils


class frida_script(object):

    def __init__(self, path: str, helper: frida_helper, name: str, restart: bool):
        self.helper = helper
        self.name = name
        self.path = path
        self.restart = restart
        self._md5 = ""

    def load(self):
        with open(path, "r") as fd:
            jscode = fd.read()
        # check md5
        md5 = hashlib.md5(jscode.encode("utf-8")).hexdigest()
        if self._md5 == md5:
            return
        self._md5 = md5
        helper.on_log("*", "Loading script: %s" % path)
        helper.detach_sessions()
        helper.run_script(package, jscode, restart=self.restart)


class frida_event_handler(FileSystemEventHandler):

    def __init__(self, script: frida_script):
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


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='easy to use frida')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + android_tools.__version__)
    parser.add_argument('-s', '--serial', action='store', default=None,
                        help='use device with given serial')

    parser.add_argument('-p', '--package', action='store', default=None,
                        help='target package [default top-level package]')

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', action='store', type=str, default=None,
                       help='javascript file')
    group.add_argument('-c', '--code', action='store', type=str, default=None,
                       help='javascript code')

    parser.add_argument('-r', '--restart', action='store_true', default=False,
                       help='inject after restart [default false]')

    args = parser.parse_args()

    observer = None
    helper = frida_helper(device_id=args.serial)
    package = args.package
    if utils.empty(package):
        package = helper.device.top_package()
    restart = args.restart

    if "-f" in sys.argv or "--file" in sys.argv:
        observer = Observer()
        path = utils.abspath(args.file)
        script = frida_script(path, helper, package, restart)
        event_handler = frida_event_handler(script)
        observer.schedule(event_handler, os.path.dirname(path))
        observer.start()
        script.load()
    elif "-c" in sys.argv or "--code" in sys.argv:
        helper.run_script(package, args.code, restart=restart)

    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        pass
