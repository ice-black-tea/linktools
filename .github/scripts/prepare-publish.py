#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : perpare.py 
@time    : 2023/04/16
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
import json
import os
import re
import subprocess

import yaml

if __name__ == '__main__':
    root_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

    ######################################################################
    # 处理版本号和release标志位
    ######################################################################
    src_path = os.path.join(root_path, "src", "linktools")
    version = os.environ["VERSION"]
    if version.startswith("v"):
        version = version[len("v"):]

    version_patten = re.compile(r"^__version__\s+=\s*\"\S*\".*$")
    release_patten = re.compile(r"^__release__\s+=\s*\w+.*$")
    with open(os.path.join(src_path, "version.py"), "rt") as fd:
        file_data = fd.read()
    with open(os.path.join(src_path, "version.py"), "wt") as fd:
        for line in file_data.splitlines(keepends=True):
            result = line
            result = version_patten.sub(f"__version__ = \"{version}\"", result)
            result = release_patten.sub(f"__release__ = True", result)
            fd.write(result)

    ######################################################################
    # 将tools.yml转为tools.json
    ######################################################################
    with open(os.path.join(src_path, "assets", "tools.yml"), "rb") as fd:
        file_data = yaml.safe_load(fd)
    with open(os.path.join(src_path, "assets", "tools.json"), "wt") as fd:
        json.dump(file_data, fd)
    os.remove(os.path.join(src_path, "assets", "tools.yml"))

    ######################################################################
    # 编译frida.min.js
    ######################################################################
    subprocess.check_call(
        "npm install && npm run build",
        shell=True,
        cwd=os.path.join(root_path, "agent", "frida")
    )

    ######################################################################
    # 编译android-tools.apk
    ######################################################################
    subprocess.check_call(
        "./gradlew --no-daemon :tools:buildTools",
        shell=True,
        cwd=os.path.join(root_path, "agent", "android")
    )
