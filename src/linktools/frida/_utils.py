#!/usr/bin/env python3
# -*- coding:utf-8 -*-

# Datetime  : 2022/11/22 18:16
# Author    : HuJi <jihu.hj@alibaba-inc.com>

import threading


class Counter:

    def __init__(self):
        self._map = {}
        self._lock = threading.RLock()

    def increase(self, group: "Group"):
        with self._lock:
            keys = group.values
            if keys not in self._map:
                self._map[keys] = 0
            self._map[keys] = self._map[keys] + 1
            return self._map[keys]

    class Group:

        def __init__(self, accept_empty: bool = False):
            self._accept_empty = accept_empty
            self._names = []
            self._values = []

        def add(self, **kwargs):
            for k, v in kwargs.items():
                if self._accept_empty or v is not None:
                    self._names.append(k)
                    self._values.append(v)
            return self

        @property
        def names(self):
            return tuple(self._names)

        @property
        def values(self):
            return tuple(self._values)

        def __repr__(self):
            return f"Group({', '.join(self._names)})"
