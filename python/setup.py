#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from setuptools import setup

if sys.version_info.major != 3:
    raise Exception("support python3 only")

setup(
    name="android tools",
    author="Hu Ji",
    version="0.0.1",
    author_email="669898595@qq.com",
    packages=["android_tools", "android_tools/commons"],
    url="https://github.com/ice-black-tea/android-library",
)
