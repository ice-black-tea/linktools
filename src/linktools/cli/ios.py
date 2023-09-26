#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import abc
from argparse import ArgumentParser
from typing import Type, List

from .command import BaseCommand
from ..ios import SibError


class IOSCommand(BaseCommand, metaclass=abc.ABCMeta):

    @property
    def known_errors(self) -> List[Type[BaseException]]:
        return super().known_errors + [SibError]

    def init_base_arguments(self, parser: ArgumentParser):
        super().init_base_arguments(parser)
        self.add_ios_arguments(parser)
