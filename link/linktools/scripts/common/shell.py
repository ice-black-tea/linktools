#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Author    : HuJi <jihu.hj@alibaba-inc.com>
# Datetime  : 2021/12/16 3:23 下午
# User      : huji
# Product   : PyCharm
# Project   : link
import os
import sys

from linktools import utils, ArgumentParser, tools
from linktools.decorator import entry_point


@entry_point(known_errors=(NotImplementedError,))
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

    if not os.path.exists(bash_path):
        raise NotImplementedError(f"file {bash_path} does not exist")

    process, _, _ = utils.exec(bash_path, *sys.argv[1:])
    exit(process.returncode)


if __name__ == "__main__":
    main()
