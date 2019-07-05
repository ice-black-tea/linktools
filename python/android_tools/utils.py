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
import re
import subprocess
import warnings
from collections import Iterable
from urllib.request import urlopen, Request

import requests
from tqdm import tqdm, TqdmSynchronisationWarning


class Utils:
    class Process(subprocess.Popen):

        def __init__(self, *args, **kwargs):
            """
            :param args: 参数
            """
            self.out = ""
            self.err = ""
            self.capture_output = utils.get_item(kwargs, "capture_output")
            if self.capture_output is True:
                kwargs["stdout"] = subprocess.PIPE
                kwargs["stderr"] = subprocess.PIPE
            if self.capture_output is not None:
                del kwargs["capture_output"]
            subprocess.Popen.__init__(self, args, shell=False, **kwargs)

        def communicate(self, **kwargs):
            out, err = None, None
            try:
                out, err = subprocess.Popen.communicate(self, **kwargs)
                if self.capture_output and out is not None:
                    self.out = self.out + out.decode(errors='ignore')
                if self.capture_output and err is not None:
                    self.err = self.err + err.decode(errors='ignore')
                return out, err
            except Exception as e:
                self.err = self.err + str(e)
            return out, err

    # noinspection PyShadowingBuiltins
    @staticmethod
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

    @staticmethod
    def int(obj: object, default: int = 0) -> int:
        """
        转为int
        :param obj: 需要转换的值
        :param default: 默认值
        :return: 转换后的值
        """
        return utils.cast(int, obj, default=default)

    @staticmethod
    def bool(obj: object, default: bool = False) -> bool:
        """
        转为bool
        :param obj: 需要转换的值
        :param default: 默认值
        :return: 转换后的值
        """
        return utils.cast(bool, obj, default=default)

    @staticmethod
    def findall(string: str, reg: str) -> [str]:
        """
        找到所有匹配的子串
        :param string: 字符串
        :param reg: 子串（正则表达式）
        :return: 匹配的子串
        """
        return re.findall(reg, string)

    @staticmethod
    def replace(string: str, reg: str, val: str, count=0) -> str:
        """
        替换子串
        :param string: 字符串
        :param reg: 子串（正则表达式）
        :param val: 替换的值
        :param count: 替换次数，为0替换所有
        :return: 替换后的值
        """
        return re.sub(reg, val, string, count=count)

    @staticmethod
    def is_match(string: str, reg: str) -> bool:
        """
        是否匹配子串
        :param string: 字符串
        :param reg: 子串（正则表达式）
        :return: 是否包含
        """
        return re.search(reg, string) is not None

    @staticmethod
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

    @staticmethod
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
    @staticmethod
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
                obj = obj[key]
            except:
                return default
        if type is not None:
            try:
                obj = type(obj)
            except:
                return default
        return obj

    # noinspection PyShadowingBuiltins
    @staticmethod
    def get_array_item(obj: object, *keys, type: type = None, default: [type(object)] = None) -> [type(object)]:
        """
        获取子项（列表）
        :param obj: 对象
        :param keys: 键
        :param type: 对应类型
        :param default: 默认值
        :return: 子项
        """
        objs = utils.get_item(obj, *keys, default=None)
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

    @staticmethod
    def exec(*args, **kwargs) -> Process:
        """
        执行命令
        :param args: 参数
        :return: 子进程
        """
        process = Utils.Process(*args, **kwargs)
        process.communicate()
        return process

    @staticmethod
    def abspath(path: str) -> str:
        """
        获取绝对路径
        :param path: 任意路径
        :return: 绝对路径
        """
        return os.path.abspath(os.path.expanduser(path))

    @staticmethod
    def basename(path: str) -> str:
        """
        获取文件名
        :param path: 任意路径
        :return: 文件名
        """
        return os.path.basename(path)

    @staticmethod
    def download(url: str, path: str) -> int:
        """
        从指定url下载文件
        :param url: 下载链接
        :param path: 保存路径
        :return: 文件大小
        """
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


utils = Utils
