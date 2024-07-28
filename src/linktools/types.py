#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author  : Hu Ji
@file    : types.py 
@time    : 2024/7/21
@site    : https://github.com/ice-black-tea
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
   /  oooooooooooooooo  .o.  oooo /,   `,"-----------
  / ==ooooooooooooooo==.o.  ooo= //   ,``--{)B     ,"
 /_==__==========__==_ooo__ooo=_/'   /___________,"
"""
import abc as _abc
import threading as _threading
import time as _time
import types as _types
import typing as _t
from pathlib import Path as _Path

if _t.TYPE_CHECKING:
    T = _t.TypeVar("T")
    P = _t.ParamSpec("P")

PathType = _t.Union[str, _Path]
QueryDataType = _t.Union[str, int, float]
QueryType = _t.Union[QueryDataType, _t.List[QueryDataType], _t.Tuple[QueryDataType]]
TimeoutType = _t.Union["Timeout", float, int, None]


class Error(Exception):
    pass


def get_origin(tp):
    if hasattr(_t, "get_origin"):
        return _t.get_origin(tp)
    if tp is _t.Generic:
        return _t.Generic
    if isinstance(tp, _types.UnionType):
        return _types.UnionType
    if hasattr(tp, "__origin__"):
        return tp.__origin__
    raise TypeError(f"{tp} has no attribute '__origin__'")


def get_args(tp):
    if hasattr(_t, "get_args"):
        return _t.get_args(tp)
    if hasattr(tp, "__args__"):
        return tp.__args__
    raise TypeError(f"{tp} has no attribute '__args__'")


class Timeout:

    def __new__(cls, timeout: TimeoutType = None):
        if isinstance(timeout, cls):
            return timeout
        elif isinstance(timeout, (float, int, type(None))):
            t = super().__new__(cls)
            t._timeout = timeout
            t._deadline = None
            t.reset()
            return t
        raise TypeError(f"Timeout/int/float was expects, got {type(timeout)}")

    @property
    def remain(self) -> _t.Union[float, None]:
        timeout = None
        if self._deadline is not None:
            timeout = max(self._deadline - _time.time(), 0)
        return timeout

    @property
    def deadline(self) -> _t.Union[float, None]:
        return self._deadline

    def reset(self) -> None:
        if self._timeout is not None and self._timeout >= 0:
            self._deadline = _time.time() + self._timeout

    def check(self) -> bool:
        if self._deadline is not None:
            if _time.time() > self._deadline:
                return False
        return True

    def ensure(self, err_type: _t.Type[Exception] = TimeoutError, message=None) -> None:
        if not self.check():
            raise err_type(message)

    def __repr__(self):
        return f"Timeout(timeout={self._timeout})"


class Event(_threading.Event):
    """
    解决 Windows 上 event.wait 不支持 ctrl+c 中断的问题
    """

    def wait(self, timeout: TimeoutType = None):
        timeout = Timeout(timeout)
        interval = 1
        wait = super().wait
        while True:
            t = timeout.remain
            if t is None:
                t = interval
            elif t <= 0:
                break
            if wait(min(t, interval)):
                break


class Stoppable(_abc.ABC):

    @_abc.abstractmethod
    def stop(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args, **kwargs):
        self.stop()


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

_proxy_fn = "_Proxy__fn"
_proxy_object = "_Proxy__object"


class Proxy(object):
    """Proxy to another object."""

    __slots__ = ('__fn', '__object', '__dict__')
    __missing__ = object()

    def __init__(self, fn=__missing__, name=None, doc=None):
        object.__setattr__(self, _proxy_fn, fn)
        object.__setattr__(self, _proxy_object, Proxy.__missing__)
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
        obj = getattr(self, _proxy_object)
        if obj == Proxy.__missing__:
            obj = getattr(self, _proxy_fn)()
            object.__setattr__(self, _proxy_object, obj)
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


class IterProxy(_t.Iterable):
    __missing__ = object()

    def __init__(self, func: "_t.Callable[P, _t.Iterable[T]]", *args: "P.args", **kwargs: "P.kwargs"):
        self._data = IterProxy.__missing__
        self._fn = func
        self._args = args
        self._kwargs = kwargs

    def __iter__(self):
        if self._data == IterProxy.__missing__:
            self._data = self._fn(*self._args, **self._kwargs)
        return iter(self._data)
