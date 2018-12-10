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
import platform
import re
import shutil
import subprocess
import sys


class system:
    _system = platform.system()

    @staticmethod
    def is_windows():  # -> bool:
        return system._system == "Windows"

    @staticmethod
    def is_linux():  # -> bool:
        return system._system == "Linux"

    @staticmethod
    def is_darwin():  # -> bool:
        return system._system == "Darwin"


if system.is_windows():
    if sys.hexversion <= 0x03000000:
        # noinspection PyUnresolvedReferences
        import _winreg as winreg
    else:
        # noinspection PyUnresolvedReferences
        import winreg
pass


class user_env:
    """
    用户环境变量
    """

    _system = platform.system()

    def __init__(self):
        """
        初始化
        """
        if system.is_windows():
            self.root = winreg.HKEY_CURRENT_USER
            self.sub_key = 'Environment'
        elif system.is_linux():
            self.bash_file = os.path.expanduser("~/.bashrc")
            self.bash_file_bak = self.bash_file + ".bak"
        elif system.is_darwin():
            self.bash_file = os.path.expanduser("~/.bash_profile")
            self.bash_file_bak = self.bash_file + ".bak"

    def get(self, key, default=""):  # -> str:
        """
        获取环境变量
        :param key:
        :param default:
        :return:
        """
        value = default
        if system.is_windows():
            reg_key = winreg.OpenKey(self.root, self.sub_key, 0, winreg.KEY_READ)
            try:
                value, _ = winreg.QueryValueEx(reg_key, key)
            except WindowsError:
                pass
        else:
            value = os.getenv(key, default)
        return value

    def set(self, key, value):  # -> None:
        """
        设置环境变量
        :param key: 键
        :param value: 值
        """
        key = key.replace("\"", "\\\"")
        value = value.replace("\"", "\\\"")

        if system.is_windows():
            command = "setx \"%s\" \"%s\"" % (key, value)
            subprocess.call(command, stdout=subprocess.PIPE)

        elif system.is_linux() or system.is_darwin():
            command_begin = "\n#-#-#-#-#-#-#-#-#-#-#-#-# written by user_env #-#-#-#-#-#-#-#-#-#-#-#-# %s\n" % key
            command_end = "\n#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-# %s\n" % key
            command_tip = "# do not modify \n"
            command = "export \"%s\"=\"%s\"" % (key, value)
            command = command_begin + command_tip + command + command_end

            bash_command = ""
            if os.path.exists(self.bash_file):
                with open(self.bash_file, "r") as fd:
                    bash_command = fd.read()
                shutil.copyfile(self.bash_file, self.bash_file_bak)

            result = re.search(r"%s[\s\S]+%s" % (command_begin, command_end), bash_command)
            if result is not None:
                span = result.span()
                bash_command = bash_command[:span[0]] + command + bash_command[span[1]:]
            else:
                bash_command = bash_command + command

            with open(self.bash_file, "w") as fd:
                fd.write(bash_command)

    def delete(self, key):  # -> None:
        """
        删除环境变量
        :param key: 键
        """
        if system.is_windows():
            reg_key = winreg.OpenKey(self.root, self.sub_key, 0, winreg.KEY_WRITE)
            try:
                winreg.DeleteValue(reg_key, key)
            except WindowsError as e:
                pass
        elif system.is_linux() or system.is_darwin():
            command_begin = "\n#-#-#-#-#-#-#-#-#-#-#-#-# written by user_env #-#-#-#-#-#-#-#-#-#-#-#-# %s\n" % key
            command_end = "\n#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-# %s\n" % key

            if os.path.exists(self.bash_file):
                with open(self.bash_file, "r") as fd:
                    bash_command = fd.read()

                result = re.search(r"%s[\s\S]+%s" % (command_begin, command_end), bash_command)
                if result is not None:
                    span = result.span()
                    bash_command = bash_command[:span[0]] + bash_command[span[1]:]

                with open(self.bash_file, "w") as fd:
                    fd.write(bash_command)


def get_module_value(source, key):
    module = ast.parse(source)
    for e in module.body:
        if isinstance(e, ast.Assign) and \
                len(e.targets) == 1 and \
                e.targets[0].id == key and \
                isinstance(e.value, ast.Str):
            return e.value.s
    raise RuntimeError('%s not found' % key)


def install_module(install):
    install_path = os.path.abspath(os.path.dirname(__file__))
    requirements_path = os.path.join(install_path, "requirements.txt")

    version_path = os.path.join(install_path, "android_tools/commons/version.py")
    with open(version_path, "rt") as f:
        source = f.read()

    if install:
        # python -m pip install -r requirements.txt -e .
        subprocess.call([sys.executable, "-m", "pip", "install",
                         "-r", requirements_path, "-e", install_path],
                        stdin=None, stdout=None, stderr=None)
    else:
        # python -m pip uninstall android_tools
        subprocess.call([sys.executable, "-m", "pip", "uninstall", get_module_value(source, "__name__")],
                        stdin=None, stdout=None, stderr=None)


def install_env(install):
    env = user_env()
    tools_key = "ANDROID_TOOLS_PATH"
    install_path = os.path.abspath(os.path.dirname(__file__))
    tools_path = os.path.join(install_path, "android_tools")

    if install:
        env.set(tools_key, tools_path)
        if system.is_windows():
            path_env = env.get("PATH")
            if tools_key not in path_env:
                path_env = "%s;%%%s%%" % (path_env, tools_key)
                env.set("PATH", path_env)
        elif system.is_linux() or system.is_darwin():
            env.set("PATH", "$PATH:$%s" % tools_key)
    else:
        env.delete(tools_key)
        if system.is_windows():
            path_env = env.get("PATH")
            if tools_key in path_env:
                env.set("PATH", path_env.replace(";%%%s%%" % tools_key, ""))
        elif system.is_linux() or system.is_darwin():
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

    if sys.version_info.major != 3:
        raise Exception("support python3 only")

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

    args = parser.parse_args()
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
