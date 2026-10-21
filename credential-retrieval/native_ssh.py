"""Transfer and run the device credential retriever over USB SSH."""

from __future__ import annotations

import atexit
from pathlib import Path
import re
import secrets
import shlex
import socket
import subprocess
import time

import paramiko


class RemoteProcess:
    def __init__(self, channel: paramiko.Channel):
        self._channel = channel
        self.stdin = channel.makefile("wb")
        self.stdout = channel.makefile("rb")
        self.stderr = channel.makefile_stderr("rb")
        self.returncode = None

    def readline_stderr(self, timeout: float) -> bytes:
        self._channel.settimeout(timeout)
        try:
            return self.stderr.readline()
        except (TimeoutError, socket.timeout):
            return b""
        finally:
            self._channel.settimeout(None)

    def communicate(self, timeout: float | None = None) -> tuple[bytes, bytes]:
        deadline = None if timeout is None else time.monotonic() + timeout
        while not self._channel.exit_status_ready():
            if deadline is not None and time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired("remote command", timeout)
            time.sleep(0.05)
        output = self.stdout.read()
        errors = self.stderr.read()
        self.returncode = self._channel.recv_exit_status()
        return output, errors

    def poll(self) -> int | None:
        if self.returncode is not None:
            return self.returncode
        if self._channel.exit_status_ready():
            self.returncode = self._channel.recv_exit_status()
            return self.returncode
        return None

    def terminate(self) -> None:
        if not self._channel.closed:
            self._channel.close()

    def wait(self, timeout: float | None = None) -> int:
        output, errors = self.communicate(timeout=timeout)
        del output, errors
        assert self.returncode is not None
        return self.returncode


class SSHDevice:
    def __init__(self, port: int, udid: str, password: str | None = None):
        if not 1 <= port <= 65535:
            raise ValueError("SSH port is out of range")
        self.tunnel = None
        self.client = None
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                pass
        except OSError:
            try:
                self.tunnel = subprocess.Popen(
                    ["ipsw", "idev", "proxy", "--no-color", "-u", udid, "--lport", str(port), "--rport", "22"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            except FileNotFoundError as exc:
                raise RuntimeError("ipsw is not installed") from exc
            atexit.register(self.close)
            for _ in range(30):
                if self.tunnel.poll() is not None:
                    raise RuntimeError("USB SSH tunnel exited before opening")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=1):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                raise RuntimeError("USB SSH tunnel did not open")
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connect = {
            "hostname": "127.0.0.1",
            "port": port,
            "username": "root",
            "timeout": 8,
            "allow_agent": password is None,
            "look_for_keys": password is None,
        }
        if password is not None:
            connect["password"] = password
        try:
            self.client.connect(**connect)
        except paramiko.AuthenticationException as exc:
            self.close()
            if password is not None:
                raise RuntimeError("SSH password was rejected") from exc
            raise RuntimeError("SSH key login failed; pass --ssh-password") from exc
        except Exception:
            self.close()
            raise
        self.directory = "/var/tmp/fp-retrieve-" + secrets.token_hex(8)
        self.trigger_directory = "/var/tmp/fp-trigger-" + secrets.token_hex(8)
        try:
            self.run("umask 077; mkdir " + shlex.quote(self.directory))
            self.run("mkdir -m 755 " + shlex.quote(self.trigger_directory))
        except Exception:
            self.close()
            raise

    def run(self, command: str, data: bytes | None = None) -> bytes:
        channel = self.client.get_transport().open_session()
        channel.settimeout(120)
        channel.exec_command(command)
        if data is not None:
            channel.sendall(data)
        channel.shutdown_write()
        stdout = b""
        stderr = b""
        while True:
            if channel.recv_ready():
                stdout += channel.recv(65536)
            if channel.recv_stderr_ready():
                stderr += channel.recv_stderr(65536)
            if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                break
            time.sleep(0.01)
        while True:
            chunk = channel.recv(65536)
            if not chunk:
                break
            stdout += chunk
        while True:
            chunk = channel.recv_stderr(65536)
            if not chunk:
                break
            stderr += chunk
        status = channel.recv_exit_status()
        channel.close()
        if status:
            message = (stdout + stderr).decode("utf-8", "replace")
            raise RuntimeError(f"device command failed ({status}): {message}")
        return stdout

    def spawn(self, command: str, **kwargs) -> RemoteProcess:
        del kwargs
        channel = self.client.get_transport().open_session()
        channel.exec_command(command)
        channel.shutdown_write()
        return RemoteProcess(channel)

    def path(self, name: str) -> str:
        if not re.fullmatch(r"[a-zA-Z0-9_.-]+", name):
            raise ValueError("invalid remote filename")
        return self.directory + "/" + name

    def write(self, name: str, source: bytes | Path, executable: bool = False) -> str:
        path = self.path(name)
        data = source.read_bytes() if isinstance(source, Path) else source
        self.run("umask 077; cat > " + shlex.quote(path), data)
        if executable:
            self.run("chmod 700 " + shlex.quote(path))
        return path

    def read(self, path: str) -> bytes:
        return self.run("cat " + shlex.quote(path))

    def cleanup(self) -> None:
        try:
            self.run("rm -r -- " + shlex.quote(self.directory) + " " + shlex.quote(self.trigger_directory))
        finally:
            self.close()

    def close(self) -> None:
        if self.client is not None:
            self.client.close()
            self.client = None
        if self.tunnel is not None and self.tunnel.poll() is None:
            self.tunnel.terminate()
            self.tunnel.wait(timeout=3)
