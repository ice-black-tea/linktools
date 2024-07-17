#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : deploy.py 
@time    : 2023/05/21
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
import re
import shutil
import textwrap

from linktools import Config, utils
from linktools.container import BaseContainer
from linktools.decorator import cached_property


class Container(BaseContainer):

    @cached_property
    def keys(self):
        # dnsapi.txt 内容从 https://github.com/acmesh-official/acme.sh/wiki/dnsapi 拷贝
        path = os.path.join(os.path.dirname(__file__), "dnsapi.txt")
        data = utils.read_file(path, text=True)
        pattern = re.compile(r'export +(\w+)="?')
        return sorted(list(set(pattern.findall(data))))

    @cached_property
    def configs(self):
        return dict(
            NGINX_TAG="1.27.0-alpine",
            WILDCARD_DOMAIN=False,
            ROOT_DOMAIN=Config.Prompt(default="_", cached=True),
            HTTP_PORT=Config.Prompt(default=80, type=int, cached=True),
            HTTPS_ENABLE=Config.Confirm(default=True, cached=True),
            HTTPS_PORT=Config.Lazy(
                lambda cfg:
                Config.Prompt(type=int, default=443, cached=True)
                if cfg.get("HTTPS_ENABLE", type=bool)
                else Config.Alias(type=int, default=0)
            ),
            ACME_DNS_API=Config.Lazy(
                lambda cfg:
                Config.Error(textwrap.dedent(
                    """
                    Ensure ACME_DNS_API config matches --dns parameter in acme command is set.
                    · Also, set corresponding environment variables.
                    · For details, see: https://github.com/acmesh-official/acme.sh/wiki/dnsapi.
                    · Example command:
                      $ ct-cntr config set ACME_DNS_API=dns_ali Ali_Key=xxx Ali_Secret=yyy
                    """
                ))
                if cfg.get("HTTPS_ENABLE", type=bool)
                else Config.Alias(type=str, default="")
            )
        )

    def on_started(self):
        utils.clear_directory(self.get_app_path("conf.d"))
        for container in self.manager.get_installed_containers():
            path = self.get_app_path("temporary", container.name)
            if os.path.isdir(path):
                shutil.copytree(
                    path,
                    self.get_app_path("conf.d", create_parent=True),
                    dirs_exist_ok=True,
                )
        self.manager.create_docker_process(
            "exec", "-it", "nginx",
            "sh", "-c", "killall nginx 1>/dev/null 2>&1"
        ).call()

    def on_removed(self):
        utils.clear_directory(self.get_app_path("temporary"))
        utils.clear_directory(self.get_app_path("conf.d"))
