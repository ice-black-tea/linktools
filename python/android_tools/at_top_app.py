#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import argparse
import datetime

import android_tools
from android_tools import device


class _top_app(object):

    def __init__(self, d: device = None):
        self._device = d
        self._package = None
        self._activity = None
        self._path = None

    @property
    def package(self):
        if self._package is None:
            self._package = self._device.top_package()
        return self._package

    @property
    def activity(self):
        if self._activity is None:
            self._activity = self._device.top_activity()
        return self._activity

    @property
    def path(self):
        if self._path is None:
            self._path = self._device.apk_path(self.package)
        return self._path


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="do something with top-level application")
    parser.add_argument('-s', '--serial', action='store', default=None,
                        help='use device with given serial')
    parser.add_argument('--show', action='store_const', const=True, default=False,
                        help='show top package path')
    parser.add_argument('--package', action='store_const', const=True, default=False,
                        help='show top-level app\'s basic infomation')
    parser.add_argument('--activity', action='store_const', const=True, default=False,
                        help='show top activity name')
    parser.add_argument('--path', action='store_const', const=True, default=False,
                        help='show top package path')
    parser.add_argument('--apk', dest='apk_path', action='store', type=str, nargs='?', default=None,
                        help='pull apk file')
    parser.add_argument('--screen', dest='screen_path', action='store', type=str,  nargs='?', default=None,
                        help='capture screen and pull file')

    args = parser.parse_args()
    if len(sys.argv) == 1:
        args.show = True

    dev = device(args.serial)
    app = _top_app(dev)

    if args.show:
        args.package = True
        args.activity = True
        args.path = True
    if args.package:
        print("package: ", app.package)
    if args.activity:
        print("activity:", app.activity)
    if args.path:
        print("path:    ", app.path)
    if "--apk" in sys.argv:
        path = dev.safe_path + app.package + ".apk"
        dev.shell("cp", app.path, path, capture_output=False)
        dev.exec("pull", path, args.apk_path, capture_output=False)
        dev.shell("rm", path)
    if "--screen" in sys.argv:
        now = datetime.datetime.now()
        path = dev.safe_path + "screenshot_" + now.strftime("%Y-%m-%d-%H-%M-%S") + ".png"
        dev.shell("screencap", "-p", path, capture_output=False)
        dev.exec("pull", path, args.screen_path, capture_output=False)
        dev.shell("rm", path)
