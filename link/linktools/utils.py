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
import contextlib
import functools
import os
import subprocess
import time
from collections import Iterable
from urllib.request import urlopen, Request

from filelock import Timeout, FileLock
from tqdm import tqdm

__module__ = __name__  # used by Proxy class body


def _default_cls_attr(name, type_, cls_value):
    # Proxy uses properties to forward the standard
    # class attributes __module__, __name__ and __doc__ to the real
    # object, but these needs to be a string when accessed from
    # the Proxy class directly.  This is a hack to make that work.
    # -- See Issue #1087.

    def __new__(cls, getter):
        instance = type_.__new__(cls, cls_value)
        instance.__getter = getter
        return instance

    def __get__(self, obj, cls=None):
        return self.__getter(obj) if obj is not None else self

    return type(name, (type_,), {
        '__new__': __new__, '__get__': __get__,
    })


class Proxy(object):
    """Proxy to another object."""

    # Code stolen from werkzeug.local.Proxy and celery.local.Proxy.
    __slots__ = ('__fn', '__object', '__dict__')
    __missing__ = object()

    def __init__(self, fn, name=None, __doc__=None):
        object.__setattr__(self, "_Proxy__fn", fn)
        object.__setattr__(self, "_Proxy__object", self.__missing__)
        if name is not None:
            object.__setattr__(self, '__custom_name__', name)
        if __doc__ is not None:
            object.__setattr__(self, '__doc__', __doc__)

    @_default_cls_attr('name', str, __name__)
    def __name__(self):
        try:
            return self.__custom_name__
        except AttributeError:
            return self._get_current_object().__name__

    @_default_cls_attr('qualname', str, __name__)
    def __qualname__(self):
        try:
            return self.__custom_name__
        except AttributeError:
            return self._get_current_object().__qualname__

    @_default_cls_attr('module', str, __module__)
    def __module__(self):
        return self._get_current_object().__module__

    @_default_cls_attr('doc', str, __doc__)
    def __doc__(self):
        return self._get_current_object().__doc__

    def _get_class(self):
        return self._get_current_object().__class__

    @property
    def __class__(self):
        return self._get_class()

    def _get_current_object(self):
        obj = getattr(self, "_Proxy__object")
        if obj == self.__missing__:
            obj = getattr(self, "_Proxy__fn")()
            object.__setattr__(self, "_Proxy__object", obj)
        return obj

    @property
    def __dict__(self):
        try:
            return self._get_current_object().__dict__
        except RuntimeError:  # pragma: no cover
            raise AttributeError('__dict__')

    def __repr__(self):
        try:
            obj = self._get_current_object()
        except RuntimeError:  # pragma: no cover
            return '<{0} unbound>'.format(self.__class__.__name__)
        return repr(obj)

    def __bool__(self):
        try:
            return bool(self._get_current_object())
        except RuntimeError:  # pragma: no cover
            return False

    __nonzero__ = __bool__  # Py2

    def __dir__(self):
        try:
            return dir(self._get_current_object())
        except RuntimeError:  # pragma: no cover
            return []

    def __getattr__(self, name):
        if name == '__members__':
            return dir(self._get_current_object())
        return getattr(self._get_current_object(), name)

    def __setitem__(self, key, value):
        self._get_current_object()[key] = value

    def __delitem__(self, key):
        del self._get_current_object()[key]

    def __setslice__(self, i, j, seq):
        self._get_current_object()[i:j] = seq

    def __delslice__(self, i, j):
        del self._get_current_object()[i:j]

    def __setattr__(self, name, value):
        setattr(self._get_current_object(), name, value)

    def __delattr__(self, name):
        delattr(self._get_current_object(), name)

    def __str__(self):
        return str(self._get_current_object())

    def __lt__(self, other):
        return self._get_current_object() < other

    def __le__(self, other):
        return self._get_current_object() <= other

    def __eq__(self, other):
        return self._get_current_object() == other

    def __ne__(self, other):
        return self._get_current_object() != other

    def __gt__(self, other):
        return self._get_current_object() > other

    def __ge__(self, other):
        return self._get_current_object() >= other

    def __hash__(self):
        return hash(self._get_current_object())

    def __call__(self, *a, **kw):
        return self._get_current_object()(*a, **kw)

    def __len__(self):
        return len(self._get_current_object())

    def __getitem__(self, i):
        return self._get_current_object()[i]

    def __iter__(self):
        return iter(self._get_current_object())

    def __contains__(self, i):
        return i in self._get_current_object()

    def __getslice__(self, i, j):
        return self._get_current_object()[i:j]

    def __add__(self, other):
        return self._get_current_object() + other

    def __sub__(self, other):
        return self._get_current_object() - other

    def __mul__(self, other):
        return self._get_current_object() * other

    def __floordiv__(self, other):
        return self._get_current_object() // other

    def __mod__(self, other):
        return self._get_current_object() % other

    def __divmod__(self, other):
        return self._get_current_object().__divmod__(other)

    def __pow__(self, other):
        return self._get_current_object() ** other

    def __lshift__(self, other):
        return self._get_current_object() << other

    def __rshift__(self, other):
        return self._get_current_object() >> other

    def __and__(self, other):
        return self._get_current_object() & other

    def __xor__(self, other):
        return self._get_current_object() ^ other

    def __or__(self, other):
        return self._get_current_object() | other

    def __div__(self, other):
        return self._get_current_object().__div__(other)

    def __truediv__(self, other):
        return self._get_current_object().__truediv__(other)

    def __neg__(self):
        return -(self._get_current_object())

    def __pos__(self):
        return +(self._get_current_object())

    def __abs__(self):
        return abs(self._get_current_object())

    def __invert__(self):
        return ~(self._get_current_object())

    def __complex__(self):
        return complex(self._get_current_object())

    def __int__(self):
        return int(self._get_current_object())

    def __float__(self):
        return float(self._get_current_object())

    def __oct__(self):
        return oct(self._get_current_object())

    def __hex__(self):
        return hex(self._get_current_object())

    def __index__(self):
        return self._get_current_object().__index__()

    def __coerce__(self, other):
        return self._get_current_object().__coerce__(other)

    def __enter__(self):
        return self._get_current_object().__enter__()

    def __exit__(self, *a, **kw):
        return self._get_current_object().__exit__(*a, **kw)

    def __reduce__(self):
        return self._get_current_object().__reduce__()


def lazy_load(fn, *args, **kwargs):
    return Proxy(functools.partial(fn, *args, **kwargs))


def popen(*args, **kwargs) -> subprocess.Popen:
    """
    打开进程
    :param args: 参数
    :return: 子进程
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
    if "shell" not in kwargs:
        kwargs["shell"] = False
    return subprocess.Popen(args, **kwargs)


def exec(*args, **kwargs) -> (subprocess.Popen, str, str):
    """
    执行命令
    :param args: 参数
    :return: 子进程
    """
    input = kwargs.pop("input", None)
    timeout = kwargs.pop("timeout", None)
    process = popen(*args, **kwargs)
    out, err = process.communicate(input=input, timeout=timeout)
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

    if obj is None:
        return obj

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

    if obj is None:
        return obj

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
        if obj is not None and type is not None:
            try:
                array.append(type(obj))
            except:
                pass
        else:
            array.append(obj)
    return array


def get_md5(data):
    import hashlib
    if type(data) == str:
        data = bytes(data, 'utf8')
    m = hashlib.md5()
    m.update(data)
    return m.hexdigest()


def gzip_compress(data):
    import gzip
    if type(data) == str:
        data = bytes(data, 'utf8')
    return gzip.compress(data)


def get_host_ip():
    import socket
    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        return s.getsockname()[0]
    except:
        return None
    finally:
        s.close()


def make_uuid():
    import uuid
    import random
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, str(uuid.uuid1()) + str(random.random())))


def make_url(url, path, **kwargs):
    from urllib import parse
    result = url.rstrip("/") + "/" + path.lstrip("/")
    if len(kwargs) > 0:
        query_string = "&".join([f"{parse.quote(key)}={parse.quote(kwargs[key])}" for key in kwargs])
        result = result + "?" + query_string
    return result


def cookie_to_dict(cookie):
    cookies = {}
    for item in cookie.split(';'):
        key_value = item.split('=', 1)
        cookies[key_value[0].strip()] = key_value[1].strip() if len(key_value) > 1 else ''
    return cookies


def download(url: str, path: str, user_agent=None, timeout=None) -> None:
    """
    从指定url下载文件
    :param url: 下载链接
    :param path: 保存路径
    :param user_agent: 下载请求头ua
    :param timeout: 超时时间
    """

    # 这个import放在这里，避免递归import
    from linktools import config

    deadline = None
    if timeout is not None:
        deadline = time.time() + timeout

    # 如果文件存在，就不下载了
    if os.path.exists(path) and os.path.getsize(path) > 0:
        return

    lock_path = path + ".lock"
    lock = FileLock(lock_path)

    try:
        lock.acquire(timeout=timeout, poll_interval=1)

        # 这时候文件存在，说明在上锁期间下载完了
        if os.path.exists(path) and os.path.getsize(path) > 0:
            return

        # 下载之前先把目录创建好
        dir_path = os.path.dirname(path)
        if not os.path.exists(dir_path):
            os.makedirs(dir_path)

        offset = 0
        download_path = path + ".download"
        # 如果文件存在，则继续上一次下载
        if os.path.exists(download_path):
            offset = os.path.getsize(download_path)

        with tqdm(unit='B', initial=offset, unit_scale=True, miniters=1, desc=os.path.split(url)[1]) as t:

            headers = {
                "User-Agent": user_agent or config["SETTING_DOWNLOAD_USER_AGENT"],
                "Range": f"bytes={offset}-"
            }

            kwargs = dict()
            kwargs["url"] = Request(url, headers=headers)

            # 根据用户传入超时时间计算得到urlopen超时时间
            if deadline is not None:
                kwargs["timeout"] = deadline - time.time()

            with contextlib.closing(urlopen(**kwargs)) as fp:

                response_headers = fp.info()
                if "content-length" in response_headers:
                    t.total = offset + int(response_headers["Content-Length"])

                with open(download_path, 'ab') as tfp:
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

        if os.path.getsize(download_path) <= 0:
            raise RuntimeError(f"download error: {url}")

        os.rename(download_path, path)

    except Timeout as e:
        raise TimeoutError(e)

    finally:
        lock.release(True)
        os.remove(lock.lock_file)
