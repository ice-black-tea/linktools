#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : at_grep.py 
@time    : 2018/12/25
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

# !/usr/bin/python

# -*- coding: utf-8 -*-
import argparse
import os
import re
import shutil
import zipfile

import magic
from colorama import Fore

import android_tools
from android_tools.decorator import try_except
from android_tools.utils import Utils


class GrepMatcher:

    def __init__(self, pattern):
        self.pattern = pattern
        self.handlers = {
            "application/zip": self.on_zip,
            "application/x-gzip": self.on_zip,
            "application/java-archive": self.on_zip,
            "application/xml": self.on_text,
        }

    def match(self, path: str):
        if not os.path.exists(path):
            return
        elif os.path.isfile(path):
            self.on_file(path)
            return
        for root, dirs, files in os.walk(path, topdown=False):
            for name in files:
                self.on_file(os.path.join(root, name))

    def on_file(self, filename: str):
        mime = magic.from_file(filename, mime=True)
        handler = Utils.get_item(self.handlers, mime)
        if handler is not None:
            if handler(filename):
                return
        elif mime.startswith("text/"):
            handler = self.on_text
            if handler(filename):
                return
        self.on_binary(filename)

    @try_except(default=False)
    def on_zip(self, filename: str) -> bool:
        dirname = filename + ":"
        while os.path.exists(dirname):
            dirname = dirname + " "
        try:
            zip_file = zipfile.ZipFile(filename, "r")
            zip_file.extractall(dirname)
            self.match(dirname)
        finally:
            shutil.rmtree(dirname, ignore_errors=True)
        return True

    @try_except(default=False)
    def on_text(self, filename: str) -> bool:
        with open(filename, "rb") as fd:
            lines = fd.readlines()
            for i in range(0, len(lines)):
                out, last, line = "", 0, lines[i].rstrip(b"\n")
                for match in self.pattern.finditer(line):
                    start, end = match.span()
                    out = out + Fore.RESET + str(line[last:start], encoding="utf-8")
                    out = out + Fore.RED + str(line[start:end], encoding="utf-8")
                    last = end
                if not Utils.is_empty(out):
                    print(Fore.CYAN + filename +
                          Fore.RESET + ":" + Fore.GREEN + str(i + 1) +
                          Fore.RESET + ": " + out +
                          Fore.RESET + str(line[last:], encoding="utf-8"))
        return True

    @try_except(default=False)
    def on_binary(self, filename: str) -> bool:
        with open(filename, "rb") as fd:
            for line in fd.readlines():
                if self.pattern.search(line) is not None:
                    print(Fore.CYAN + filename + Fore.RESET + ": binary file match")
                    break
        return True


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='match files with regular expression')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + android_tools.__version__)

    parser.add_argument('pattern', action='store', default=None,
                        help='regular expression')
    parser.add_argument('files', metavar="file", action='store', nargs='*', default=None,
                        help='target files path')
    parser.add_argument('-i', '--ignore-case', action='store_true', default=False,
                        help='ignore case')

    args = parser.parse_args()

    flags = 0
    if args.ignore_case:
        flags = flags | re.I
    pattern = re.compile(bytes(args.pattern, encoding="utf8"), flags=flags)

    if Utils.is_empty(args.files):
        args.files = ["."]

    for file in args.files:
        GrepMatcher(pattern).match(file)
