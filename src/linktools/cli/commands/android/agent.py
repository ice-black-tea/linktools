#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : at_call_agent.py
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
   /  oooooooooooooooo  .o.  oooo /,   `,"-----------
  / ==ooooooooooooooo==.o.  ooo= //   ,``--{)B     ,"
 /_==__==========__==_ooo__ooo=_/'   /___________,"
"""
import os
from argparse import ArgumentParser, Namespace
from typing import Optional

from linktools.android import Device
from linktools.cli import AndroidCommand, CommandError


class Command(AndroidCommand):
    """
    Debug and interact with android-tools.apk for troubleshooting
    """

    def init_arguments(self, parser: ArgumentParser) -> None:
        parser.add_argument("-p", "--privilege", action="store_true", default=False,
                            help="run with root privilege")
        parser.add_argument("-u", "--user", action="store",
                            help="run with user privilege")
        parser.add_argument("--data", metavar="PATH", action="store",
                            help="data path")
        parser.add_argument("--library", metavar="PATH", action="store",
                            help="library path")
        parser.add_argument("--plugin", metavar="PATH", action="store",
                            help="plugin file path")
        parser.add_argument("agent_args", nargs="...", help="agent args")

    def run(self, args: Namespace) -> Optional[int]:
        device = args.device_picker.pick()

        process = device.popen(
            *device.make_shell_args(
                *device.make_agent_args(
                    *args.agent_args,
                    data_path=args.data or device.get_data_path('agent', 'data'),
                    library_path=args.library,
                    plugin_path=self._push_plugin(device, args.plugin),
                ),
                privilege=args.privilege,
                user=args.user
            )
        )
        return process.call()

    @classmethod
    def _push_plugin(cls, device: Device, path: str = None) -> Optional[str]:
        if not path:
            return None
        if not os.path.exists(path):
            raise CommandError(f"Plugin file not found: {path}")
        plugin_name = os.path.basename(path)
        plugin_path = device.get_data_path("agent", "plugin", plugin_name)
        device.push(path, plugin_path)
        return plugin_path


command = Command()
if __name__ == "__main__":
    command.main()
