#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : config.py 
@time    : 2021/08/04
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

import errno
import json
import os
from types import ModuleType
from typing import Optional, Union, Callable, IO, Any, Mapping, Dict


class Config(dict):

    def __init__(self, defaults: Optional[dict] = None):
        dict.__init__(self, defaults or {})

    def from_pyfile(self, filename: str, silent: bool = False) -> bool:
        d = ModuleType("config")
        d.__file__ = filename
        try:
            with open(filename, mode="rb") as config_file:
                exec(compile(config_file.read(), filename, "exec"), d.__dict__)
        except OSError as e:
            if silent and e.errno in (errno.ENOENT, errno.EISDIR, errno.ENOTDIR):
                return False
            e.strerror = f"Unable to load configuration file ({e.strerror})"
            raise
        self.from_object(d)
        return True

    def from_object(self, obj: Union[object, str]) -> None:
        for key in dir(obj):
            if key.isupper():
                self[key] = getattr(obj, key)

    def from_file(self, filename: str, load: Callable[[IO[Any]], Mapping], silent: bool = False) -> bool:

        try:
            with open(filename) as f:
                obj = load(f)
        except OSError as e:
            if silent and e.errno in (errno.ENOENT, errno.EISDIR):
                return False

            e.strerror = f"Unable to load configuration file ({e.strerror})"
            raise

        return self.from_mapping(obj)

    def from_mapping(self, mapping: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> bool:
        mappings: Dict[str, Any] = {}
        if mapping is not None:
            mappings.update(mapping)
        mappings.update(kwargs)
        for key, value in mappings.items():
            if key.isupper():
                self[key] = value
        return True

    def get_namespace(self, namespace: str, lowercase: bool = True, trim_namespace: bool = True) -> Dict[str, Any]:
        rv = {}
        for k, v in self.items():
            if not k.startswith(namespace):
                continue
            if trim_namespace:
                key = k[len(namespace) :]
            else:
                key = k
            if lowercase:
                key = key.lower()
            rv[key] = v
        return rv


def create_config():
    config = Config()
    config_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "configs"))
    for root, dirs, files in os.walk(config_path):
        for name in files:
            if name.endswith(".py"):
                config.from_pyfile(os.path.join(root, name))
            elif name.endswith(".json"):
                config.from_file(os.path.join(root, name), load=json.load)
    return config
