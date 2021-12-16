#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Author    : HuJi <jihu.hj@alibaba-inc.com>
# Datetime  : 2021/12/16 3:23 下午
# User      : huji
# Product   : PyCharm
# Project   : link
import os

from linktools import utils, ArgumentParser, tools
from linktools.decorator import entry_point


@entry_point()
def main():

    if tools.system in ["darwin", "linux"]:
        bash_path = "/bin/bash"
        if "SHELL" in os.environ:
            bash_path = os.environ["SHELL"]
    elif tools.system in ["windows"]:
        bash_path = "C:\\WINDOWS\\system32\\cmd.exe"
        if "ComSpec" in os.environ:
            bash_path = os.environ["ComSpec"]
    else:
        raise NotImplementedError(f"unsupported system {tools.system}")

    parser = ArgumentParser(description=f'exec {bash_path}')
    parser.add_argument('cmd', nargs='...')

    args = parser.parse_args()
    process, _, _ = utils.exec(bash_path, *args.cmd)
    exit(process.returncode)


if __name__ == "__main__":
    main()
