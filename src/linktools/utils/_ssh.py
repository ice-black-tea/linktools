#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import contextlib
import sys
import threading
from socket import socket

import paramiko
from paramiko.ssh_exception import AuthenticationException, SSHException
from rich import get_console
from rich.prompt import Prompt
from scp import SCPClient

from . import list2cmdline
from ._utils import ignore_error
from .._logging import get_logger, create_log_progress

_logger = get_logger("utils.ssh")


class SSHClient(paramiko.SSHClient):

    def connect_with_pwd(self, hostname, port=22, username=None, password=None, **kwargs):
        try:
            super().connect(
                hostname,
                port=port,
                username=username,
                password=password,
                **kwargs
            )
        except SSHException:

            if password is not None:
                raise

            transport = self.get_transport()
            if transport is None:
                raise
            elif not transport.is_alive():
                raise
            elif transport.is_authenticated():
                raise

            auth_exception = None
            for i in range(3):
                console = get_console()
                password = Prompt.ask(
                    f"{username}@{hostname}'s password",
                    console=console,
                    password=True
                )
                try:
                    transport.auth_password(username, password)
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
            shell = self._windows_shell

            try:
                import termios
                import tty
                shell = self._posix_shell
            except ImportError:
                pass

            try:
                shell(chan)
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
                try:
                    data = sock.recv(1024)
                    if not data:
                        sys.stdout.flush()
                        break
                    sys.stdout.write(data.decode())
                    sys.stdout.flush()
                except OSError:
                    break

        writer = threading.Thread(target=write_all, args=(channel,))
        writer.start()
        while True:
            try:
                data = sys.stdin.read(1)
                if len(data) == 0:
                    break
                channel.send(data.encode())
            except OSError:
                break

    def get_file(self, remote_path: str, local_path: str):
        with self._open_scp() as scp:
            return scp.get(remote_path, local_path, recursive=True)

    def put_file(self, local_path: str, remote_path: str):
        with self._open_scp() as scp:
            return scp.put(local_path, remote_path, recursive=True)

    @contextlib.contextmanager
    def _open_scp(self):

        with create_log_progress() as progress:
            task_id = progress.add_task("", total=0)
            progress.advance(task_id, 0)

            def update_progress(filename, size, sent):
                if isinstance(filename, bytes):
                    filename = filename.decode()
                progress.update(
                    task_id,
                    completed=sent,
                    description=filename,
                    total=size
                )

            with SCPClient(self.get_transport(), progress=update_progress) as scp:
                yield scp
