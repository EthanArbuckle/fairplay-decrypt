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


class SSHDevice:
    def __init__(self, port: int, udid: str):
        if not 1 <= port <= 65535:
            raise ValueError("SSH port is out of range")
        self.tunnel = None
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
        self.command = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=8", "-p", str(port), "root@127.0.0.1"]
        self.directory = "/var/tmp/fp-retrieve-" + secrets.token_hex(8)
        self.trigger_directory = "/var/tmp/fp-trigger-" + secrets.token_hex(8)
        self.run("umask 077; mkdir " + shlex.quote(self.directory))
        self.run("mkdir -m 755 " + shlex.quote(self.trigger_directory))

    def run(self, command: str, data: bytes | None = None) -> bytes:
        result = subprocess.run(self.command + [command], input=data, capture_output=True, timeout=120)
        if result.returncode:
            message = (result.stdout + result.stderr).decode("utf-8", "replace")
            raise RuntimeError(f"device command failed ({result.returncode}): {message}")
        return result.stdout

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
        if self.tunnel is not None and self.tunnel.poll() is None:
            self.tunnel.terminate()
            self.tunnel.wait(timeout=3)
