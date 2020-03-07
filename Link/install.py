#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : install.py 
@time    : 2018/11/26
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
import ast
import os
import subprocess
import sys

from linktools import version
from linktools.environment import UserEnv

env = UserEnv()


def install_module(install):
    install_path = os.path.abspath(os.path.dirname(__file__))

    version_path = os.path.join(install_path, "linktools", "version.py")
    with open(version_path, "rt") as f:
        _module = ast.parse(f.read())

    if install:
        install_require(True)
        # python -m pip install -e .
        subprocess.call([sys.executable, "-m", "pip", "install", "-e", install_path],
                        stdin=None, stdout=None, stderr=None)
    else:
        # python -m pip uninstall linktools
        subprocess.call([sys.executable, "-m", "pip", "uninstall", version.__name__],
                        stdin=None, stdout=None, stderr=None)


def install_env(install):
    tools_key = "LINK_TOOLS_PATH"
    install_path = os.path.abspath(os.path.dirname(__file__))
    tools_path = os.path.join(install_path, "linktools", "modules")

    if install:
        env.set(tools_key, tools_path)
        if env.is_windows:
            path_env = env.get("PATH")
            if tools_key not in path_env:
                path_env = "{key};%%{value}%%".format(key=path_env, value=tools_key)
                env.set("PATH", path_env)
        elif env.is_linux or env.is_darwin:
            env.set("PATH", "$PATH:${value}".format(value=tools_key))
    else:
        env.delete(tools_key)
        if env.is_windows:
            path_env = env.get("PATH")
            if tools_key in path_env:
                env.set("PATH", path_env.replace(";%%{value}%%".format(value=tools_key), ""))
        elif env.is_linux or env.is_darwin:
            env.delete("PATH")


def install_require(install):
    install_path = os.path.abspath(os.path.dirname(__file__))
    requirements_path = os.path.join(install_path, "requirements.txt")
    platform_path = os.path.join(install_path, "resource", "requirements", "{platform}.txt".format(platform=env.platform_name))

    if install:
        # python -m pip install -r requirements.txt
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", requirements_path, "-r", platform_path],
                              stdin=None, stdout=None, stderr=None)
    else:
        # python -m pip uninstall -r requirements.txt
        subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "-r", requirements_path, "-r", platform_path],
                              stdin=None, stdout=None, stderr=None)


if __name__ == '__main__':

    if (sys.version_info.major, sys.version_info.minor) < (3, 5):
        raise Exception("only supports python 3.5 or higher")

    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-i', '--install', action='store_const', const=True, default=False,
                       help='install python module and set environmental variable')
    group.add_argument('--install-module', action='store_const', const=True, default=False,
                       help='install python module only')
    group.add_argument('--install-env', action='store_const', const=True, default=False,
                       help='set environmental variable only')
    group.add_argument('-u', '--uninstall', action='store_const', const=True, default=False,
                       help='uninstall python module and reset environmental variable')
    group.add_argument('--uninstall-module', action='store_const', const=True, default=False,
                       help='uninstall python module only')
    group.add_argument('--uninstall-env', action='store_const', const=True, default=False,
                       help='reset environmental variable only')
    group.add_argument('--uninstall-require', action='store_const', const=True, default=False,
                       help='uninstall requirements only')

    if env.bash_file is not None:
        parser.add_argument("--bash-file", metavar="PATH", action='store', default=env.bash_file,
                            help='bash file path [default {path}]'.format(path=env.bash_file))

    args = parser.parse_args()

    try:
        if env.bash_file is not None:
            env.bash_file = args.bash_file
            if not os.path.exists(env.bash_file):
                raise Exception("{path} is not exists".format(path=env.bash_file))

        if args.install:
            install_module(True)
            install_env(True)
        elif args.install_module:
            install_module(True)
        elif args.install_env:
            install_env(True)
        elif args.uninstall:
            install_module(False)
            install_env(False)
        elif args.uninstall_env:
            install_env(False)
        elif args.uninstall_module:
            install_module(False)
        elif args.uninstall_require:
            install_require(False)
        else:
            install_module(True)
            install_env(True)

    except Exception as e:
        print(e, file=sys.stderr)
