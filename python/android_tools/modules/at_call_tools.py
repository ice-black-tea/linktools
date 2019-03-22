#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : at_call_tools.py
@time    : 2018/12/02
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

from android_tools.adb import Device, AdbError
from android_tools.argparser import AdbArgumentParser


def main():
    parser = AdbArgumentParser(description='used for debugging android-tools.apk')

    adb, args = parser.parse_adb_args()
    parser.parse_known_args(args)
    device = Device(adb.extend())
    device.call_tools(*args, capture_output=False)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
    except EOFError:
        pass
    except AdbError as e:
        print(e)
