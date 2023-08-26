#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import abc
from argparse import ArgumentParser
from typing import Tuple, Type

from .command import BaseCommand
from ..ios import SibError


class IOSCommand(BaseCommand, metaclass=abc.ABCMeta):

    @property
    def known_errors(self) -> Tuple[Type[BaseException]]:
        return super().known_errors + tuple([SibError])

    def init_base_arguments(self, parser: ArgumentParser):
        super().init_base_arguments(parser)
        self.add_ios_arguments(parser)
