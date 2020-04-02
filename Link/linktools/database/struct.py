#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : database.py 
@time    : 2020/03/31
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

class Field:

    def __init__(self, name: str, is_private_key: bool, is_bind_value: bool, default_value: object):
        self.name = name
        self.is_private_key = is_private_key
        self.is_bind_value = is_bind_value
        self.default_value=default_value

    def get(self, instance):
        pass

    def set(self, instance, value):
        pass

    def __str__(self):
        return self.name


class Table:

    _cached_tables = {}

    def __init__(self, name: str, fields: [Field]):
        self.name = name
        self.fields = fields

    @staticmethod
    def from_model(model):
        return Table.from_class(model.__class__)

    @staticmethod
    def from_class(cls):
        if cls not in Table._cached_tables:
            raise Exception("decorate {} with @table".format(cls.__name__))
        return Table._cached_tables[cls]

    def __str__(self):
        return "Table ({}, Fields={})".format(self.name, ",".join(str(x) for x in self.fields))
