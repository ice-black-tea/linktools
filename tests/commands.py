#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import os
import unittest

from linktools.__main__ import Command
from linktools.cli import walk_commands


class TestCommands(unittest.TestCase):

    def test_help(self):
        for category in Command.module_categories:
            path = os.path.join(Command.module_path, category.name)
            for command in walk_commands(path):
                with self.subTest(command.name, command=command):
                    self.assertEqual(command(["--help"]), 0)


if __name__ == '__main__':
    unittest.main()
