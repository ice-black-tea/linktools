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
   /  oooooooooooooooo  .o.  oooo /,   \,"-----------
  / ==ooooooooooooooo==.o.  ooo= //   ,`\--{)B     ,"
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
            NGINX_TAG="alpine",
            ROOT_DOMAIN=Config.Prompt(cached=True),
            WILDCARD_DOMAIN=Config.Confirm(default=False, cached=True),
            HTTP_PORT=Config.Prompt(default=80, type=int, cached=True),
            HTTPS_PORT=Config.Prompt(default=443, type=int, cached=True),
            ACME_DNS_API=Config.Error(textwrap.dedent(
                """
                Ensure ACME_DNS_API config matches --dns parameter in acme command is set.
                · Also, set corresponding environment variables.
                · For details, see: https://github.com/acmesh-official/acme.sh/wiki/dnsapi.
                · Example command:
                  $ ct-cntr config set ACME_DNS_API=dns_ali Ali_Key=xxx Ali_Secret=yyy
                """
            ))
        )

    @cached_property
    def enable(self):
        return self.manager.config.get(
            "NGINX_ENABLE",
            type=bool,
            default=Config.Confirm(default=True, cached=True)
        )

    def on_starting(self):
        path = self.get_app_path("conf.d")
        if not os.path.exists(path):
            return
        for name in os.listdir(path):
            target_path = os.path.join(path, name)
            if os.path.isdir(target_path):
                shutil.rmtree(target_path, ignore_errors=True)
            else:
                utils.ignore_error(os.remove, args=(target_path,))

    def on_started(self):
        self.manager.change_owner(
            self.get_app_path(),
            self.manager.user
        )
