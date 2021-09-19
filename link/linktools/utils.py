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
import functools
import os
import subprocess
from collections import Iterable


class _LazyLoad(object):
    __missing__ = object()

    def __init__(self, fn):
        object.__setattr__(self, "_LazyLoad__fn", fn)
        object.__setattr__(self, "_LazyLoad__object", self.__missing__)

    def __get_object(self):
        obj = getattr(self, "_LazyLoad__object")
        if obj == self.__missing__:
            obj = getattr(self, "_LazyLoad__fn")()
            object.__setattr__(self, "_LazyLoad__object", obj)
        return obj

    def __getattr__(self, name):
        return getattr(self.__get_object(), name)

    def __setattr__(self, name, value):
        setattr(self.__get_object(), name, value)

    def __delattr__(self, name):
        delattr(self.__get_object(), name)

    def __getitem__(self, name):
        return self.__get_object()[name]

    def __setitem__(self, name, value):
        self.__get_object()[name] = value

    def __delitem__(self, key):
        del self.__get_object()[key]

    def __len__(self, key):
        return len(self.__get_object())

    def __iter__(self):
        return iter(self.__get_object())

    def __repr__(self):
        return repr(self.__get_object())

    def __str__(self):
        return str(self.__get_object())


def lazy_load(fn, *args, **kwargs):
    return _LazyLoad(functools.partial(fn, *args, **kwargs))


class _Process(subprocess.Popen):

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


def popen(*args, **kwargs) -> subprocess.Popen:
    """
    打开进程
    :param args: 参数
    :return: 子进程
    """
    return _Process(*args, **kwargs)


def exec(*args, **kwargs) -> (subprocess.Popen, str, str):
    """
    执行命令
    :param args: 参数
    :return: 子进程
    """
    process = _Process(*args, **kwargs)
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


def download(url: str, path: str, proxies=None) -> int:
    """
    从指定url下载文件
    :param url: 下载链接
    :param path: 保存路径
    :return: 文件大小
    """
    from urllib.request import urlopen, Request
    from tqdm import tqdm
    from linktools import config

    import contextlib

    dir_path = os.path.dirname(path)
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)
    tmp_path = path + ".download"

    offset = 0
    if os.path.exists(tmp_path):
        offset = os.path.getsize(tmp_path)

    with tqdm(unit='B', initial=offset, unit_scale=True, miniters=1, desc=os.path.split(url)[1]) as t:

        request_headers = {
            "User-Agent": config["DOWNLOAD_USER_AGENT"],
            "Range": f"bytes={offset}-"
        }

        with contextlib.closing(urlopen(Request(url, headers=request_headers))) as fp:

            response_headers = fp.info()
            if "content-length" in response_headers:
                t.total = offset + int(response_headers["Content-Length"])

            with open(tmp_path, 'ab') as tfp:
                bs = 1024 * 8
                read = 0

                t.update(offset + read - t.n)

                while True:
                    block = fp.read(bs)
                    if not block:
                        break
                    read += len(block)
                    tfp.write(block)

                    t.update(offset + read - t.n)

    size = os.path.getsize(tmp_path)
    if size <= 0:
        raise RuntimeError(f"download error: {url}")
    os.rename(tmp_path, path)

    return size
