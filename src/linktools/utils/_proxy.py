#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Datetime  : 2022/11/4 下午1:18
# Author    : HuJi <jihu.hj@alibaba-inc.com>

import functools
from typing import TYPE_CHECKING, TypeVar, Type, Callable, Iterable

if TYPE_CHECKING:
    from typing import ParamSpec

    T = TypeVar("T")
    P = ParamSpec("P")

_PROXY_FN = "_Proxy__fn"
_PROXY_OBJECT = "_Proxy__object"
_PROXY_MISSING = ...


# Code stolen from celery.local.Proxy: https://github.com/celery/celery/blob/main/celery/local.py

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


__module__ = __name__  # used by Proxy class body


class _Proxy(object):
    """Proxy to another object."""

    __slots__ = ('__fn', '__object', '__dict__')

    def __init__(self, fn, name=None, doc=None):
        object.__setattr__(self, _PROXY_FN, fn or _PROXY_MISSING)
        object.__setattr__(self, _PROXY_OBJECT, _PROXY_MISSING)
        if name is not None:
            object.__setattr__(self, "__custom_name__", name)
        if doc is not None:
            object.__setattr__(self, "__doc__", doc)

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
        obj = getattr(self, _PROXY_OBJECT)
        if obj == _PROXY_MISSING:
            obj = getattr(self, _PROXY_FN)()
            object.__setattr__(self, _PROXY_OBJECT, obj)
        return obj

    @property
    def __dict__(self):
        return self._get_current_object().__dict__

    def __repr__(self):
        return repr(self._get_current_object())

    def __bool__(self):
        return bool(self._get_current_object())

    __nonzero__ = __bool__  # Py2

    def __dir__(self):
        return dir(self._get_current_object())

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


def get_derived_type(t: "Type[T]") -> "Type[T]":
    """
    生成委托类型，常用于自定义类继承委托类，替换某些方法, 如：

    import subprocess

    class Popen(get_derived_type(subprocess.Popen)):
        __super__: subprocess.Popen

        def communicate(self, *args, **kwargs):
            out, err = self.__super__.communicate(*args, **kwargs)
            return 'fake out!!!', 'fake error!!!'

    process = Popen(subprocess.Popen(["/usr/bin/git", "status"]))
    print(process.communicate())  # ('fake out!!!', 'fake error!!!')

    :param t: 需要委托的类型
    :return: 同参数t，需要委托的类型
    """

    class Derived(_Proxy):

        def __init__(self, obj: "T"):
            super().__init__(_PROXY_MISSING)
            object.__setattr__(self, "__super__", obj)

        def _get_current_object(self):
            return self.__super__

    return Derived


def lazy_load(fn: "Callable[P, T]", *args: "P.args", **kwargs: "P.kwargs") -> "T":
    """
    延迟加载
    :param fn: 延迟加载的方法
    :return: proxy
    """
    return _Proxy(functools.partial(fn, *args, **kwargs))


def lazy_iter(fn: "Callable[P, Iterable[T]]", *args: "P.args", **kwargs: "P.kwargs") -> "Iterable[T]":
    """
    延迟迭代
    :param fn: 延迟迭代的方法
    :return: proxy
    """

    class IterProxy(Iterable):

        def __init__(self):
            self._data: Iterable[T] = _PROXY_MISSING

        def __iter__(self):
            if self._data == _PROXY_MISSING:
                self._data = fn(*args, **kwargs)
            return iter(self._data)

    return IterProxy()


def raise_error(e: BaseException):
    raise e


def lazy_raise(e: BaseException) -> "T":
    return lazy_load(raise_error, e)
