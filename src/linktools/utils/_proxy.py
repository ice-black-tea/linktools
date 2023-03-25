#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Datetime  : 2022/11/4 下午1:18
# Author    : HuJi <jihu.hj@alibaba-inc.com>

import functools
from typing import TypeVar, Type, Callable


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
    __missing__ = object()

    def __init__(self, fn=None, obj=None, name=None, __doc__=None):
        if fn is None and obj is None:
            raise ValueError('fn and obj arguments may not be "None" at the same time')
        elif fn is not None and obj is not None:
            raise ValueError('fn and obj arguments may not be specified at the same time')
        object.__setattr__(self, "_Proxy__fn", fn or self.__missing__)
        object.__setattr__(self, "_Proxy__object", obj or self.__missing__)
        if name is not None:
            object.__setattr__(self, "__custom_name__", name)
        if __doc__ is not None:
            object.__setattr__(self, "__doc__", __doc__)

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


_T = TypeVar('_T')


def get_derived_type(t: Type[_T]) -> Type[_T]:
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

        def __init__(self, obj: _T):
            super().__init__(obj=obj)

        @property
        def __super__(self) -> _T:
            return self._get_current_object()

    return Derived


def lazy_load(fn: Callable[..., _T], *args, **kwargs) -> _T:
    """
    延迟加载
    :param fn: 延迟加载的方法
    :return: proxy
    """
    return _Proxy(functools.partial(fn, *args, **kwargs))


def lazy_raise(e: Exception) -> _T:
    """
    延迟抛出异常
    :param e: exception
    :return: proxy
    """

    def raise_error():
        raise e

    return lazy_load(raise_error)
