#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : file.py 
@time    : 2019/01/11
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


class file_matcher(object):

    def __init__(self, name: str):
        self.name = name

    def match(self):
        """
        开始匹配
        :return: None
        """
        if not os.path.exists(self.name):
            raise Exception("")
        handler = self.on_dir if os.path.isdir(self.name) else self.on_file
        handler(self.name)

    def on_file(self, filename: str):
        """
        匹配文件
        :param filename: 文件名
        :return: None
        """
        raise Exception("not yet implemented")

    def on_dir(self, dirname: str):
        """
        匹配目录
        :param dirname: 目录名
        :return: None
        """
        for name in os.listdir(dirname):
            filename = os.path.join(dirname, name)
            handler = self.on_dir if os.path.isdir(filename) else self.on_file
            handler(filename)