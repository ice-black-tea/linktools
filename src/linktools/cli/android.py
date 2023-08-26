#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import abc
from argparse import ArgumentParser
from typing import Tuple, Type

from .command import BaseCommand
from ..android import AdbError


class AndroidCommand(BaseCommand, metaclass=abc.ABCMeta):

    @property
    def known_errors(self) -> Tuple[Type[BaseException]]:
        return super().known_errors + tuple([AdbError])

    def init_base_arguments(self, parser: ArgumentParser):
        super().init_base_arguments(parser)
        self.add_android_arguments(parser)
