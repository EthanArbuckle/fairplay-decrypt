"""Transfer and run the device credential retriever over USB SSH."""

from __future__ import annotations

import atexit
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import time


class SSHDevice:
    def __init__(self, port: int, udid: str, user: str = "root", password: str | None = None):
        if not 1 <= port <= 65535:
            raise ValueError("SSH port is out of range")
        self.tunnel = None
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                pass
        except OSError:
            self.tunnel = subprocess.Popen(["iproxy", "-u", udid, f"{port}:22"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
        auth = ["-o", "BatchMode=yes"] if password is None else []
        self.command = ["ssh", *auth, "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=8", "-p", str(port), f"{user}@127.0.0.1"]
        self.env = None
        if password is not None:
            if shutil.which("sshpass") is None:
                self.close()
                raise RuntimeError("password SSH needs sshpass on PATH")
            self.command = ["sshpass", "-e", *self.command]
            self.env = {**os.environ, "SSHPASS": password}
        temporary = self.run("if command -v jbroot >/dev/null 2>&1; then jbroot /var/tmp; fi").decode("utf-8").strip()
        self.ps = "/rootfs/bin/ps" if temporary else "ps"
        if temporary and not temporary.startswith("/"):
            self.close()
            raise RuntimeError("jbroot returned a non-absolute temporary directory")
        # Native programs do not use the bootstrap shell's virtual filesystem.
        temporary = temporary or "/var/tmp"
        self.directory = temporary + "/fp-retrieve-" + secrets.token_hex(8)
        self.trigger_directory = temporary + "/fp-trigger-" + secrets.token_hex(8)
        self.run("umask 077; mkdir " + shlex.quote(self.directory))
        self.run("mkdir -m 755 " + shlex.quote(self.trigger_directory))

    def run(self, command: str, data: bytes | None = None) -> bytes:
        result = subprocess.run(self.command + [command], input=data, capture_output=True, timeout=120, env=self.env)
        if result.returncode:
            message = (result.stdout + result.stderr).decode("utf-8", "replace")
            raise RuntimeError(f"device command failed ({result.returncode}): {message}")
        return result.stdout

    def popen(self, command: str, **kwargs) -> subprocess.Popen:
        return subprocess.Popen(self.command + [command], env=self.env, **kwargs)

    def processes(self) -> bytes:
        return self.run(shlex.quote(self.ps) + " -e -o pid,comm")

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
