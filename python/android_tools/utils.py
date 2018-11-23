#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import subprocess
import warnings
from urllib.request import urlopen

import requests
from tqdm import tqdm, TqdmSynchronisationWarning


class _process(subprocess.Popen):

    def __init__(self, command, stdin, stdout, stderr):
        """
        :param command: 命令
        :param stdin: 输入流
        :param stdout: 输出流
        :param stderr: 错误输出流
        """
        self.out = ""
        self.err = ""
        self.returncode = -0x7fffffff
        subprocess.Popen.__init__(self, command, shell=True, stdin=stdin, stdout=stdout, stderr=stderr)

    def communicate(self, **kwargs):
        out, err = None, None
        try:
            out, err = subprocess.Popen.communicate(self, **kwargs)
            if out is not None:
                self.out = self.out + out.decode(errors='ignore')
            if err is not None:
                self.err = self.err + err.decode(errors='ignore')
            return out, err
        except Exception as e:
            self.err = self.err + str(e)
        return out, err


class utils:

    PIPE = subprocess.PIPE
    STDOUT = subprocess.STDOUT

    @staticmethod
    def is_empty(obj: object):
        """
        对象是否为空
        :param obj: 对象
        :return: 是否为空
        """
        if obj is None:
            return True
        if type(obj) in [str, bytes, tuple, list, dict]:
            # noinspection PyTypeChecker
            return obj is None or len(obj) == 0
        return True

    @staticmethod
    def is_contain(obj: object, key: object, value=None):
        """
        是否包含内容
        :param obj: 对象
        :param key: 键
        :param value: 值
        :return: 是否包含
        """
        if obj is None:
            return False
        if type(obj) is dict:
            return key in obj and (value is None or obj[key] == value)
        return key in obj

    @staticmethod
    def int(obj, default: int = 0):
        try:
            return int(obj)
        except:
            return default

    @staticmethod
    def bool(obj, default: bool = False):
        try:
            return bool(obj)
        except:
            return default

    @staticmethod
    def exec(command: str, stdin=PIPE, stdout=PIPE, stderr=PIPE) -> _process:
        """
        执行命令
        :param command: 命令
        :param stdin: 输入流，默认为utils.PIPE，标准输入为None
        :param stdout: 输出流，默认为utils.PIPE，标准输出为None
        :param stderr: 错误输出流，默认为utils.PIPE，输出到输出流为utils.STDOUT，标准输出为None
        :param background: 是否后台运行
        :return: 子进程
        """
        process = _process(command, stdin, stdout, stderr)
        process.communicate()
        return process

    @staticmethod
    def download_from_url(url: str, file_path: str) -> int:
        """
        从指定url下载文件
        :param url: 下载链接
        :param file_path: 下载路径
        :return: 文件大小
        """
        file_dir = os.path.dirname(file_path)
        if not os.path.exists(file_dir):
            os.makedirs(file_dir)
        if os.path.exists(file_path):
            first_byte = os.path.getsize(file_path)
        else:
            first_byte = 0
        file_size = int(urlopen(url).info().get('Content-Length', -1))
        if first_byte >= file_size:
            return file_size
        header = {"Range": "bytes=%s-%s" % (first_byte, file_size)}
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", TqdmSynchronisationWarning)
            pbar = tqdm(total=file_size, initial=first_byte, unit='B', unit_scale=True, desc=url.split('/')[-1])
            req = requests.get(url, headers=header, stream=True)
            with (open(file_path, 'ab')) as f:
                for chunk in req.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)
                        pbar.update(1024)
                    pass
                pass
            pbar.close()
        return file_size
