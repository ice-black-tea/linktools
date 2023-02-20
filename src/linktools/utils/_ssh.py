#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import functools
import sys
import threading
from socket import socket

import paramiko
from paramiko.ssh_exception import AuthenticationException
from rich import get_console
from rich.prompt import Prompt

from . import list2cmdline
from ._utils import ignore_error
from .._logging import get_logger

_logger = get_logger("utils.ssh")


class SSHClient(paramiko.SSHClient):

    def connect_with_password(self, hostname, *, username=None, password=None, **kwargs):
        try:
            super().connect(
                hostname,
                username=username,
                password=password,
                **kwargs
            )
        except AuthenticationException:
            if password is not None:
                raise

            auth_exception = None
            for i in range(3):
                console = get_console()
                password = Prompt.ask(
                    f"{username}@{self.get_transport().hostname}'s password",
                    console=console,
                    password=True
                )
                try:
                    self.get_transport().auth_password(username, password)
                    auth_exception = None
                    break
                except AuthenticationException as e:
                    auth_exception = e

            if auth_exception is not None:
                raise auth_exception

    def open_shell(self, *args: any):
        if len(args) > 0:
            stdin, stdout, stderr = self.exec_command(
                list2cmdline([str(arg) for arg in args]),
                get_pty=True
            )

            def iter_lines(io1, io2):
                for line in iter(io1.readline, ""):
                    print(line, end="", file=io2)

            threads = [
                threading.Thread(target=iter_lines, args=(stdout, sys.stdout)),
                threading.Thread(target=iter_lines, args=(stderr, sys.stdout)),
            ]

            for thread in threads:
                thread.start()

            for thread in threads:
                thread.join()

        else:
            chan = self.invoke_shell()
            try:
                import termios
                import tty
                self._posix_shell(chan)
            except ImportError:
                self._windows_shell(chan)
            finally:
                ignore_error(chan.close)

    @classmethod
    def _posix_shell(cls, channel: "paramiko.Channel"):
        import select
        import termios
        import tty

        orig_tty = None

        try:
            orig_tty = termios.tcgetattr(sys.stdin.fileno())
            tty.setraw(sys.stdin.fileno())
            tty.setcbreak(sys.stdin.fileno())
        except Exception as e:
            _logger.debug(f"Set tty error: {e}")

        try:
            channel.settimeout(1)
            while True:
                rlist, wlist, xlist = select.select([channel, sys.stdin], [], [], 1)
                if channel in rlist:
                    try:
                        data = channel.recv(1024)
                        if len(data) == 0:
                            break
                        sys.stdout.write(data.decode())
                        sys.stdout.flush()
                    except socket.timeout:
                        pass
                if sys.stdin in rlist:
                    data = sys.stdin.read(1)
                    if len(data) == 0:
                        break
                    channel.send(data.encode())
        finally:
            if orig_tty:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, orig_tty)

    @classmethod
    def _windows_shell(cls, channel: "paramiko.Channel"):
        import threading

        def write_all(sock):
            while True:
                data = sock.recv(1024)
                if not data:
                    sys.stdout.flush()
                    break
                sys.stdout.write(data.decode())
                sys.stdout.flush()

        writer = threading.Thread(target=write_all, args=(channel,))
        writer.start()
        while True:
            data = sys.stdin.read(1)
            if len(data) == 0:
                break
            channel.send(data.encode())
