#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : decorator.py 
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
from inspect import isfunction, isclass

from linktools.database.struct import Field, Table


def table(name: str=None):

    if name is not None and type(name) != str and not isclass(name):
        raise Exception("@table only decorates class")

    def wrapper(*args, **kwargs):
        if isclass(name):
            cls = name
            table_name = cls.__name__
        else:
            cls = args[0]
            table_name = name or cls.__name__

        if not isclass(cls):
            raise Exception("@table only decorates class")

        fields = []
        for key in cls.__dict__:
            field = cls.__dict__[key]
            if isinstance(field, Field):
                fields.append(field)
        Table._cached_tables[cls] = Table(
            name=table_name,
            fields=fields
        )

        return cls(*args, **kwargs) if isclass(name) else cls

    return wrapper


def field(name: str=None, default_value: object=None, is_private_key=False, is_bind_value=True):

    if name is not None and type(name) != str and not isfunction(name):
        raise Exception("@field only decorates function")

    class wrapper(Field):
        _missing = object()

        def __init__(self, *args):
            if isfunction(name):
                fn = name
                field_name = fn.__name__
            else:
                fn = args[0]
                field_name = name or fn.__name__

            if not isfunction(fn):
                raise Exception("@field only decorates function")

            super().__init__(
                name=field_name,
                is_private_key=is_private_key,
                is_bind_value=is_bind_value,
                default_value=default_value
            )
            self.__name__ = fn.__name__
            self.__module__ = fn.__module__
            self.__doc__ = fn.__doc__
            self.func = fn

        def __get__(self, instance, owner):
            if instance is None:
                return self
            value = instance.__dict__.get(self.__name__, self._missing)
            if value == self._missing:
                value = self.func(instance)
                instance.__dict__[self.__name__] = value
            return value

        def __set__(self, instance, value):
            if instance is not None:
                instance.__dict__[self.__name__] = value

        def get(self, instance):
            return self.__get__(instance, None)

        def set(self, instance, value):
            return self.__set__(instance, value)

    return wrapper() if isfunction(name) else wrapper
