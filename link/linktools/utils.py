#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : utils.py
@time    : 2018/11/25
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
import subprocess
import warnings
from collections import Iterable


class LazyLoad(object):
    __slots__ = ("__var", "__dict__", "__name__", "__wrapped__")
    __missing__ = object()

    def __init__(self, variable, name=None):
        object.__setattr__(self, "_LazyLoad__var", variable)
        object.__setattr__(self, "__name__", name)
        object.__setattr__(self, "__value__", self.__missing__)
        object.__setattr__(self, "__wrapped__", variable)

    def _get_current_object(self):
        value = getattr(self, "__value__")
        if value != self.__missing__:
            return value
        value = self.__var()
        object.__setattr__(self, "__value__", value)
        return value

    def __getattr__(self, name):
        return getattr(self._get_current_object(), name)

    def __setattr__(self, name, value):
        setattr(self._get_current_object(), name, value)

    def __delattr__(self, name):
        delattr(self._get_current_object(), name)

    def __getitem__(self, name):
        return self._get_current_object()[name]

    def __setitem__(self, name, value):
        self._get_current_object()[name] = value

    def __delitem__(self, key):
        del self._get_current_object()[key]

    def __len__(self, key):
        return len(self._get_current_object())

    def __iter__(self):
        return iter(self._get_current_object())

    def __repr__(self):
        return repr(self._get_current_object())


class Process(subprocess.Popen):

    def __init__(self, *args, **kwargs):
        """
        :param args: 参数
        """
        if "capture_output" in kwargs:
            capture_output = kwargs.pop("capture_output")
            if capture_output is True:
                if "stdout" not in kwargs:
                    kwargs["stdout"] = subprocess.PIPE
                if "stderr" not in kwargs:
                    kwargs["stderr"] = subprocess.PIPE
        if "cwd" not in kwargs:
            kwargs["cwd"] = os.getcwd()
        subprocess.Popen.__init__(self, args, shell=False, **kwargs)


def popen(*args, **kwargs) -> Process:
    """
    打开进程
    :param args: 参数
    :return: 子进程
    """
    return Process(*args, **kwargs)


def exec(*args, **kwargs) -> (Process, str, str):
    """
    执行命令
    :param args: 参数
    :return: 子进程
    """
    process = Process(*args, **kwargs)
    out, err = process.communicate()
    return process, out, err


# noinspection PyShadowingBuiltins
def cast(type: type, obj: object, default: type(object) = None) -> type(object):
    """
    类型转换
    :param type: 目标类型
    :param obj: 对象
    :param default: 默认值
    :return: 转换后的值
    """
    try:
        return type(obj)
    except:
        return default


def int(obj: object, default: int = 0) -> int:
    """
    转为int
    :param obj: 需要转换的值
    :param default: 默认值
    :return: 转换后的值
    """
    return cast(type(0), obj, default=default)


def bool(obj: object, default: bool = False) -> bool:
    """
    转为bool
    :param obj: 需要转换的值
    :param default: 默认值
    :return: 转换后的值
    """
    return cast(type(True), obj, default=default)


def is_contain(obj: object, key: object) -> bool:
    """
    是否包含内容
    :param obj: 对象
    :param key: 键
    :return: 是否包含
    """
    if object is None:
        return False
    if isinstance(obj, Iterable):
        return key in obj
    return False


def is_empty(obj: object) -> bool:
    """
    对象是否为空
    :param obj: 对象
    :return: 是否为空
    """
    if obj is None:
        return True
    if isinstance(obj, Iterable):
        # noinspection PyTypeChecker
        return obj is None or len(obj) == 0
    return False


# noinspection PyShadowingBuiltins
def get_item(obj: object, *keys, type: type = None, default: type(object) = None) -> type(object):
    """
    获取子项
    :param obj: 对象
    :param keys: 键
    :param type: 对应类型
    :param default: 默认值
    :return: 子项
    """
    for key in keys:
        if obj is None:
            return default
        try:
            # noinspection PyUnresolvedReferences
            obj = obj[key]
            continue
        except:
            pass
        try:
            obj = obj.__dict__[key]
        except:
            return default
    if type is not None:
        try:
            obj = type(obj)
        except:
            return default
    return obj


# noinspection PyShadowingBuiltins
def pop_item(obj: object, *keys, type: type = None, default: type(object) = None) -> type(object):
    """
    获取并删除子项
    :param obj: 对象
    :param keys: 键
    :param type: 对应类型
    :param default: 默认值
    :return: 子项
    """
    last_obj = None
    last_key = None
    for key in keys:
        if obj is None:
            return default
        last_obj = obj
        last_key = key
        try:
            # noinspection PyUnresolvedReferences
            obj = obj[key]
            continue
        except:
            pass
        try:
            obj = obj.__dict__[key]
        except:
            return default
    if last_obj is not None and last_key is not None:
        try:
            # noinspection PyUnresolvedReferences
            del last_obj[last_key]
        except:
            pass
    if type is not None:
        try:
            obj = type(obj)
        except:
            return default
    return obj


# noinspection PyShadowingBuiltins
def get_array_item(obj: object, *keys, type: type = None, default: [type(object)] = None) -> [type(object)]:
    """
    获取子项（列表）
    :param obj: 对象
    :param keys: 键
    :param type: 对应类型
    :param default: 默认值
    :return: 子项
    """
    objs = get_item(obj, *keys, default=None)
    if objs is None or not isinstance(objs, Iterable):
        return default
    array = []
    for obj in objs:
        if type is not None:
            try:
                array.append(type(obj))
            except:
                pass
        else:
            array.append(obj)
    return array


def abspath(path: str) -> str:
    """
    获取绝对路径
    :param path: 任意路径
    :return: 绝对路径
    """
    return os.path.abspath(os.path.expanduser(path))


def basename(path: str) -> str:
    """
    获取文件名
    :param path: 任意路径
    :return: 文件名
    """
    return os.path.basename(path)


def cookie_to_dict(cookie):
    cookies = {}
    for item in cookie.split(';'):
        key_value = item.split('=', 1)
        cookies[key_value[0].strip()] = key_value[1].strip() if len(key_value) > 1 else ''
    return cookies


def download(url: str, path: str) -> int:
    """
    从指定url下载文件
    :param url: 下载链接
    :param path: 保存路径
    :return: 文件大小
    """
    import requests
    from tqdm import tqdm, TqdmSynchronisationWarning
    from urllib.request import urlopen, Request

    dir = os.path.dirname(path)
    if not os.path.exists(dir):
        os.makedirs(dir)
    tmp_path = path + ".download"
    if os.path.exists(tmp_path):
        offset = os.path.getsize(tmp_path)
    else:
        offset = 0

    user_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36"
    size = int(urlopen(Request(url, headers={"User-Agent": user_agent})).info().get('Content-Length', -1))
    if size == -1:
        raise Exception("error Content-Length")
    if offset >= size:
        return size
    header = {"User-Agent": user_agent, "Range": "bytes=%s-%s" % (offset, size)}
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", TqdmSynchronisationWarning)
        pbar = tqdm(total=size, initial=offset, unit='B', unit_scale=True, desc=url.split('/')[-1])
        req = requests.get(url, headers=header, stream=True)
        with (open(tmp_path, 'ab')) as fd:
            for chunk in req.iter_content(chunk_size=1024):
                if chunk:
                    fd.write(chunk)
                    pbar.update(1024)
        pbar.close()
    os.rename(tmp_path, path)
    return size
