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

from watchdog.events import *
from watchdog.observers import Observer

from linktools import utils, logger
from linktools.android import AdbError, AdbArgumentParser

try:
    # noinspection PyPackageRequirements
    from frida import ServerNotRunningError
    from linktools.android.frida import FridaHelper
except ModuleNotFoundError:
    logger.error("please use the following command to install frida first:",
                 sys.executable, "-m", "pip", "install", "frida")
    exit(1)


class FridaScript(object):

    def __init__(self, path: str, helper: FridaHelper, name: str, regular: bool, restart: bool):
        self.helper = helper
        self.name = name
        self.regular = regular
        self.path = path
        self.restart = restart
        self.last_md5 = ""

    def load(self):
        with open(self.path, "r") as fd:
            jscode = fd.read()
        # check md5
        md5 = hashlib.md5(jscode.encode("utf-8")).hexdigest()
        if self.last_md5 == md5:
            return
        self.last_md5 = md5

        logger.info("Loading script: %s" % self.path, tag="[*]")
        self.helper.detach_sessions()

        if not self.restart:
            processes = self.helper.get_processes(self.name) if not self.regular \
                else filter(lambda x: re.match(self.name, x.name), self.helper.get_processes())
            self.helper.run_script(processes, jscode)
        else:
            self.helper.restart_and_run_script(self.name, jscode)


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
    parser.add_argument('--regular', action='store_true', default=False,
                        help="regular match package name")
    parser.add_argument('file', action='store', default=None,
                        help='javascript file')

    args = parser.parse_args()
    helper = FridaHelper(device_id=args.parse_adb_serial())

    package = args.package
    if utils.is_empty(package):
        package = helper.device.get_top_package_name()

    observer = Observer()
    path = utils.abspath(args.file)
    script = FridaScript(path, helper, package, args.regular, args.restart)
    event_handler = FridaEventHandler(script)
    observer.schedule(event_handler, os.path.dirname(path))
    observer.start()
    script.load()

    sys.stdin.read()


if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt, EOFError, FileNotFoundError) as e:
        logger.error(e)
    except (AdbError, ServerNotRunningError) as e:
        logger.error(e)
    except Exception as e:
        logger.error(traceback_error=True)
