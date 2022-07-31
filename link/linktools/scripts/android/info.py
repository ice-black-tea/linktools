#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : info.py 
@time    : 2022/07/31
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
from colorama import Fore

from linktools import logger
from linktools.android import AdbError, AndroidArgumentParser, Device
from linktools.decorator import entry_point

props = (
    "ro.product.manufacturer",
    "ro.product.model",
    "ro.product.name",
    "ro.board.platform",
    "ro.build.version.release",
    "ro.build.version.base_os",
    "ro.build.version.sdk",
    "ro.build.version.incremental",
    "ro.build.version.security_patch",
    "ro.odm.build.id",
    "ro.build.fingerprint",
    "ro.build.build.fingerprint",
    "ro.bootimage.build.fingerprint",
    "ro.odm.build.fingerprint",
    "ro.product.build.fingerprint",
    "ro.system_ext.build.fingerprint",
    "ro.system.build.fingerprint",
    "ro.vendor.build.fingerprint",
)

files = (
    "/proc/sys/kernel/random/boot_id",  # 重启后变化
    "/proc/sys/kernel/random/uuid",
    "/sys/block/mmcblk0/device/cid",
    "/sys/devices/soc0/serial_number",
    "/proc/misc",
    "/proc/version",
)

cmds = (
    ("uname", ("uname -a",)),
    ("magisk df", ("df | grep /sbin/.magisk",)),
    ("magisk mount", ("mount | grep /sbin/.magisk",)),
    ("magisk process", ("df | ps | grep magisk",)),
    ("ip", ("ip a",)),
)


@entry_point(logger_tag=True, known_errors=[AdbError])
def main():
    parser = AndroidArgumentParser(description='fetch device information')
    parser.add_argument('agent_args', nargs='...', help="agent args")
    args = parser.parse_args()
    device: Device = args.parse_device()

    logger.info(f"Property", fore=Fore.RED)
    for prop in props:
        logger.info(f"{prop}: {device.get_prop(prop)}", indent=2)

    logger.info(f"File", fore=Fore.RED)
    for file in files:
        logger.info(f"{file}: {device.shell('cat', file, ignore_error=True).strip()}", indent=2)

    logger.info(f"Cmdline", fore=Fore.RED)
    for cmd in cmds:
        logger.info(f"{cmd[0]}: {device.shell(*cmd[1], ignore_error=True).strip()}", indent=2)


if __name__ == '__main__':
    main()
