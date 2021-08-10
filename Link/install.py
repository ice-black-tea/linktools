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
import os
import subprocess
import sys

from linktools import version
from linktools.environ import UserEnviron

env = UserEnviron()


def install_module(install):
    install_path = os.path.abspath(os.path.dirname(__file__))

    if install:
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

    if env.bash_file is not None:
        if not os.path.exists(env.bash_file):
            raise Exception("{path} is not exists".format(path=env.bash_file))

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

    if install:
        # python -m pip install -r requirements.txt
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", requirements_path],
                              stdin=None, stdout=None, stderr=None)
    else:
        # python -m pip uninstall -r requirements.txt
        subprocess.check_call([sys.executable, "-m", "pip", "uninstall", "-r", requirements_path],
                              stdin=None, stdout=None, stderr=None)


if __name__ == '__main__':

    if (sys.version_info.major, sys.version_info.minor) < (3, 5):
        raise Exception("only supports python 3.5 or higher")

    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-i', '--install', action='store_const', const=True, default=False,
                       help='install python module only')
    group.add_argument('-u', '--uninstall', action='store_const', const=True, default=False,
                       help='uninstall python module only')

    group = parser.add_argument_group("additional arguments")
    group.add_argument('--module', action='store_const', const=True, default=False,
                       help='install/uninstall module')
    group.add_argument('--require', action='store_const', const=True, default=False,
                       help='install/uninstall requirements')
    group.add_argument('--env', action='store_const', const=True, default=False,
                       help='install/uninstall environment variables')

    if env.is_linux or env.is_darwin:
        group.add_argument('--bash-file', metavar="PATH", action='store', default=env.bash_file,
                           help='bash file path is required (default: %(default)s)')

    args = parser.parse_args()

    install = args.uninstall is not True

    actions = []
    if args.require:
        actions.append(install_require)
    if args.module:
        actions.append(install_module)
    if args.env:
        actions.append(install_env)
        if env.is_linux or env.is_darwin:
            env.bash_file = args.bash_file
    if len(actions) == 0:
        actions.append(install_require)
        actions.append(install_module)

    try:
        for action in actions:
            action(install)
    except Exception as e:
        print(e, file=sys.stderr)
