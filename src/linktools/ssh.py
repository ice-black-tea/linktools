#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import contextlib
import getpass
import os
import select
import socket
import sys
import threading

import paramiko
from paramiko.ssh_exception import AuthenticationException, SSHException
from scp import SCPClient

from . import utils
from ._environ import environ
from .reactor import Stoppable
from .rich import create_progress, prompt
from .utils import list2cmdline, ignore_error

try:
    import SocketServer
except ImportError:
    import socketserver as SocketServer

_logger = environ.get_logger("ssh")


class SSHClient(paramiko.SSHClient):

    def connect_with_pwd(self, hostname, port=22, username=None, password=None, **kwargs):
        if username is None:
            username = getpass.getuser()

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
                password = prompt(
                    f"{username}@{hostname}'s password",
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
                threading.Thread(target=iter_lines, args=(stderr, sys.stderr)),
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
        stdin_fileno = sys.stdin.fileno()

        try:
            orig_tty = termios.tcgetattr(stdin_fileno)
            tty.setraw(stdin_fileno)
            tty.setcbreak(stdin_fileno)
        except Exception as e:
            _logger.debug(f"Set tty error: {e}")

        try:
            channel.settimeout(0.0)
            while True:
                rlist, wlist, xlist = select.select([channel, sys.stdin], [], [], 1.0)
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
                    data = os.read(stdin_fileno, 1)
                    if len(data) == 0:
                        break
                    channel.send(data)
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
                    if len(data) == 0:
                        sys.stdout.flush()
                        break
                    sys.stdout.write(data.decode())
                    sys.stdout.flush()
                except OSError:
                    break

        write_thread = threading.Thread(target=write_all, args=(channel,))
        write_thread.start()

        stdin_fileno = sys.stdin.fileno()
        while True:
            try:
                data = os.read(stdin_fileno, 1)
                if len(data) == 0:
                    break
                channel.send(data)
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

        with create_progress() as progress:
            tasks = {}

            def update_progress(filename, size, sent):
                if isinstance(filename, bytes):
                    filename = filename.decode()
                task_id = tasks.get(filename, None)
                if task_id is None:
                    task_id = progress.add_task(filename, total=size)
                    tasks[filename] = task_id
                progress.update(
                    task_id,
                    completed=sent,
                    description=filename,
                    total=size
                )

            with SCPClient(self.get_transport(), progress=update_progress) as scp:
                yield scp

    def forward(self, forward_host: str, forward_port: int, local_port: int = None):

        if local_port is None:
            local_port = utils.pick_unused_port(range(20000, 30000))

        class ForwardServer(SocketServer.ThreadingTCPServer):
            daemon_threads = True
            allow_reuse_address = True

        channels = []
        lock = threading.RLock()
        transport = self.get_transport()

        class ForwardHandler(SocketServer.BaseRequestHandler):

            def handle(self):
                try:
                    channel = transport.open_channel(
                        "direct-tcpip",
                        (forward_host, forward_port),
                        self.request.getpeername(),
                    )
                except Exception as e:
                    _logger.error(
                        "Incoming request to %s:%d failed: %s"
                        % (forward_host, forward_port, repr(e))
                    )
                    return

                if channel is None:
                    _logger.error(
                        "Incoming request to %s:%d was rejected by the SSH server."
                        % (forward_host, forward_port)
                    )
                    return

                with lock:
                    channels.append(channel)

                try:
                    _logger.debug(
                        "Connected!  Tunnel open %r -> %r -> %r"
                        % (
                            self.request.getpeername(),
                            channel.getpeername(),
                            (forward_host, forward_port),
                        )
                    )
                    while True:
                        r, w, x = select.select([self.request, channel], [], [])
                        if self.request in r:
                            data = self.request.recv(1024)
                            if len(data) == 0:
                                break
                            channel.send(data)
                        if channel in r:
                            data = channel.recv(1024)
                            if len(data) == 0:
                                break
                            self.request.send(data)
                except Exception as e:
                    _logger.debug(
                        "Forwarding request to %s:%d failed: %r"
                        % (forward_host, forward_port, e)
                    )
                finally:
                    peername = utils.ignore_error(self.request.getpeername)
                    utils.ignore_error(channel.close)
                    utils.ignore_error(self.request.close)
                    _logger.debug(
                        "Tunnel closed from %r" %
                        (peername,)
                    )

                    with lock:
                        channels.remove(channel)

        forward_server = ForwardServer(("", local_port), ForwardHandler)
        forward_thread = threading.Thread(target=forward_server.serve_forever)
        forward_thread.daemon = True
        forward_thread.start()

        class Forward(Stoppable):

            local_port = property(lambda self: local_port)
            forward_host = property(lambda self: forward_host)
            forward_port = property(lambda self: forward_port)

            def stop(self):
                try:
                    forward_server.shutdown()
                    forward_thread.join()
                except Exception as e:
                    _logger.error(
                        "Cancel port forward failed: %r"
                        % e
                    )

                with lock:
                    for channel in channels:
                        utils.ignore_error(channel.close)

        return Forward()

    def reverse(self, forward_host: str, forward_port: int, remote_port: int = None):

        channels = []
        lock = threading.RLock()

        def forward_handler(channel):

            sock = socket.socket()
            try:
                sock.connect((forward_host, forward_port))
            except Exception as e:
                utils.ignore_error(channel.close)
                utils.ignore_error(sock.close)
                _logger.error(
                    "Forwarding request to %s:%d failed: %r"
                    % (forward_host, forward_port, e)
                )
                return

            with lock:
                channels.append(channel)

            try:
                _logger.debug(
                    "Connected!  Tunnel open %r -> %r -> %r"
                    % (channel.origin_addr, channel.getpeername(), (forward_host, forward_port))
                )
                while True:
                    r, w, x = select.select([sock, channel], [], [])
                    if sock in r:
                        data = sock.recv(1024)
                        if len(data) == 0:
                            break
                        channel.send(data)
                    if channel in r:
                        data = channel.recv(1024)
                        if len(data) == 0:
                            break
                        sock.send(data)
            except Exception as e:
                _logger.debug(
                    "Forwarding request to %s:%d failed: %r"
                    % (forward_host, forward_port, e)
                )
            finally:
                utils.ignore_error(channel.close)
                utils.ignore_error(sock.close)
                _logger.debug(
                    "Tunnel closed from %r"
                    % (channel.origin_addr,)
                )

                with lock:
                    channels.remove(channel)

        class ForwardThread(threading.Thread):

            def __init__(self):
                super().__init__()
                self.event = threading.Event()

            def run(self):
                while not self.event.is_set():
                    channel = transport.accept(.5)
                    if channel is None:
                        continue
                    thread = threading.Thread(
                        target=forward_handler, args=(channel,)
                    )
                    thread.daemon = True
                    thread.start()

            def shutdown(self):
                self.event.set()

        transport = self.get_transport()
        remote_port = transport.request_port_forward("", remote_port or 0)

        forward_thread = ForwardThread()
        forward_thread.daemon = True
        forward_thread.start()

        class Reverse(Stoppable):

            remote_port = property(lambda self: remote_port)
            forward_host = property(lambda self: forward_host)
            forward_port = property(lambda self: forward_port)

            def stop(self):
                try:
                    transport.cancel_port_forward("", remote_port)
                    forward_thread.shutdown()
                    forward_thread.join()
                except Exception as e:
                    _logger.error(
                        f"Cancel port forward failed: %r"
                        % e
                    )

                with lock:
                    for channel in channels:
                        utils.ignore_error(channel.close)

        return Reverse()
