#!/usr/bin/env python3
"""Run the native credential retriever on a jailbroken device over USB SSH."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import plistlib
import re
import select
import shlex
import subprocess
import time
from zipfile import ZipFile

from native_ssh import SSHDevice

ROOT = Path(__file__).resolve().parent
BUNDLE = ROOT / "build" / "bundle"
DEVICE_FILES = ("credential.ios", "selector21.ios", "trigger.ios", "static-key-table.bin", "core4-word-table.bin")
MAX_SINF_BYTES = 1 << 20


def connected_udid() -> str:
    try:
        result = subprocess.run(["ipsw", "idev", "list", "--json", "--no-color"], capture_output=True, text=True, timeout=10)
    except FileNotFoundError as exc:
        raise RuntimeError("ipsw is not installed") from exc
    if result.returncode:
        message = (result.stdout + result.stderr).strip() or f"exit {result.returncode}"
        raise RuntimeError(f"ipsw idev list failed: {message}")
    payload = result.stdout.strip()
    if not payload:
        devices = []
    else:
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise RuntimeError("ipsw idev list did not return JSON") from exc
        if not isinstance(parsed, list):
            raise RuntimeError("ipsw idev list JSON must be an array")
        devices = []
        for item in parsed:
            if not isinstance(item, dict) or "unique_device_id" not in item:
                raise RuntimeError("ipsw idev list JSON is missing unique_device_id")
            devices.append(normalize_udid(item["unique_device_id"]))
    if len(devices) != 1:
        raise RuntimeError(f"connect exactly one device; found {len(devices)}")
    return devices[0]


def normalize_udid(value: str) -> str:
    value = value.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise ValueError("device UDID must contain 40 hexadecimal digits")
    return value


def children(data: bytes, start: int, end: int):
    at = start
    while at < end:
        if at + 8 > end:
            raise ValueError("truncated SINF atom")
        size = int.from_bytes(data[at : at + 4], "big")
        if size < 8 or at + size > end:
            raise ValueError("invalid SINF atom size")
        yield data[at + 4 : at + 8], at + 8, at + size
        at += size


def sinf_field(sinf: bytes, tag: bytes) -> bytes:
    root = list(children(sinf, 0, len(sinf)))
    if len(root) != 1 or root[0][0] != b"sinf":
        raise ValueError("expected one complete SINF atom")
    schi = [item for item in children(sinf, root[0][1], root[0][2]) if item[0] == b"schi"]
    if len(schi) != 1:
        raise ValueError("expected one SINF schi container")
    fields = [item for item in children(sinf, schi[0][1], schi[0][2]) if item[0] == tag]
    if len(fields) != 1:
        raise ValueError(f"expected one SINF {tag!r} field")
    return sinf[fields[0][1] : fields[0][2]]


def supported_sinf(sinf: bytes) -> bool:
    try:
        priv = sinf_field(sinf, b"priv")
        sinf_field(sinf, b"name")
        return len(sinf_field(sinf, b"user")) == 4 and len(sinf_field(sinf, b"key ")) == 4 and len(sinf_field(sinf, b"iviv")) == 16 and (len(priv) == 448 or (len(priv) == 440 and priv[-8:] == bytes(8)))
    except ValueError:
        return False


def license_sinf(raw_path: Path | None, ipa_path: Path | None, member: str | None) -> bytes:
    if raw_path is not None:
        if member:
            raise ValueError("--sinf-member requires --ipa")
        if raw_path.stat().st_size > MAX_SINF_BYTES:
            raise ValueError("SINF is too large")
        sinf = raw_path.read_bytes()
    else:
        if ipa_path is None:
            raise ValueError("supply --sinf or --ipa")
        with ZipFile(ipa_path) as archive:
            names = sorted(name for name in archive.namelist() if "/SC_Info/" in name and name.endswith(".sinf") and not name.endswith(".v4.sinf"))
            if member:
                if member not in names:
                    raise ValueError("--sinf-member is not a supported SINF")
                names = [member]
            selectors = {}
            for name in names:
                if archive.getinfo(name).file_size > MAX_SINF_BYTES:
                    continue
                candidate = archive.read(name)
                try:
                    if not supported_sinf(candidate):
                        continue
                    selector = (sinf_field(candidate, b"user"), sinf_field(candidate, b"key "))
                except ValueError:
                    continue
                selectors.setdefault(selector, []).append((name, candidate))
            if len(selectors) != 1:
                raise ValueError(f"IPA has {len(selectors)} distinct license selectors; choose one with --sinf-member")
            sinf = min(next(iter(selectors.values())), key=lambda item: (item[0].count("/"), item[0]))[1]
    if len(sinf) > MAX_SINF_BYTES:
        raise ValueError("SINF is too large")
    list(children(sinf, 0, len(sinf)))
    if len(sinf) < 8 or sinf[4:8] != b"sinf" or int.from_bytes(sinf[:4], "big") != len(sinf):
        raise ValueError("expected one complete SINF atom")
    if not supported_sinf(sinf):
        raise ValueError("license format is not supported")
    return sinf


def write_new(path: Path, data: bytes) -> None:
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(data)


def trigger_app(device: SSHDevice, license_bytes: bytes | None) -> tuple[str, str, bytes]:
    account = sinf_field(license_bytes, b"user") if license_bytes is not None else None
    listing = device.run("find /var/containers/Bundle/Application -type f -path '*/SC_Info/*.sinf' -print0")
    for raw_path in sorted(path for path in listing.split(b"\0") if path and not path.endswith(b".v4.sinf")):
        path = raw_path.decode("utf-8", "surrogateescape")
        bundle = Path(path).parent.parent
        if bundle.suffix != ".app":
            continue
        try:
            installed_sinf = device.read(path)
            if len(installed_sinf) > MAX_SINF_BYTES or (account is not None and sinf_field(installed_sinf, b"user") != account):
                continue
            if license_bytes is None and not supported_sinf(installed_sinf):
                continue
            info = plistlib.loads(device.read(str(bundle / "Info.plist")))
            executable = info["CFBundleExecutable"]
            if not isinstance(executable, str) or executable in ("", ".", "..") or "/" in executable:
                continue
            return str(bundle), executable, installed_sinf
        except (KeyError, ValueError, plistlib.InvalidFileException):
            continue
    raise RuntimeError("no installed App Store app has a supported license for the selected account")


def fairplayd_pid(device: SSHDevice) -> int:
    listing = device.run("ps -e -o pid,comm").decode("utf-8", "replace")
    pids = []
    for line in listing.splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) == 2 and fields[0].isdigit() and re.fullmatch(r"fairplayd(?:\.A[0-9]+)?", Path(fields[1]).name):
            pids.append(int(fields[0]))
    if len(pids) != 1:
        raise RuntimeError(f"expected one fairplayd process; found {len(pids)}")
    return pids[0]


def restart_fairplayd(device: SSHDevice) -> int:
    previous = fairplayd_pid(device)
    device.run(f"kill -TERM {previous}")
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            current = fairplayd_pid(device)
        except RuntimeError:
            current = previous
        if current != previous:
            return current
        time.sleep(0.1)
    raise RuntimeError("fairplayd did not restart")


def remote_pids(device: SSHDevice, executable: str) -> list[int]:
    listing = device.run("ps -e -o pid,comm").decode("utf-8", "replace")
    result = []
    for line in listing.splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) == 2 and fields[0].isdigit() and fields[1] == executable:
            result.append(int(fields[0]))
    return result


def stop_remote(device: SSHDevice, executable: str) -> None:
    for pid in remote_pids(device, executable):
        device.run(f"kill -TERM {pid}")


def observe_uid_layer(device: SSHDevice, program: str, pid: int, output: str, trigger_program: str, executable: str) -> None:
    command = " ".join(map(shlex.quote, (program, "observe-uid-layer", str(pid), output, "90")))
    observer = subprocess.Popen(device.command + [command], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    trigger_process = None
    direct_process = None
    try:
        if not select.select([observer.stderr], [], [], 15)[0]:
            raise RuntimeError("FairPlay observer did not become ready")
        ready = observer.stderr.readline()
        if b"observing selector 21" not in ready:
            raise RuntimeError("FairPlay observer failed: " + ready.decode("utf-8", "replace"))
        trigger_command = " ".join(map(shlex.quote, (trigger_program, executable)))
        trigger_process = subprocess.Popen(device.command + [trigger_command], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        trigger_output, trigger_errors = trigger_process.communicate(timeout=15)
        if trigger_process.returncode:
            failure = trigger_output + trigger_errors
            if trigger_process.returncode != 3:
                raise RuntimeError("FairPlay trigger failed: " + failure.decode("utf-8", "replace"))
            direct_process = subprocess.Popen(device.command + [shlex.quote(executable)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        output_bytes, errors = observer.communicate(timeout=100)
        if observer.returncode:
            raise RuntimeError("FairPlay observation failed: " + (output_bytes + errors).decode("utf-8", "replace"))
    finally:
        stop_remote(device, trigger_program)
        if direct_process is not None:
            stop_remote(device, executable)
            if direct_process.poll() is None:
                direct_process.terminate()
                direct_process.wait(timeout=10)
        if trigger_process is not None and trigger_process.poll() is None:
            trigger_process.terminate()
            trigger_process.wait(timeout=10)
        if observer.poll() is None:
            stop_remote(device, program)
            observer.communicate(timeout=10)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, default=BUNDLE, help="device bundle directory (default: credential-retrieval/build/bundle)")
    license_group = parser.add_mutually_exclusive_group()
    license_group.add_argument("--ipa", type=Path, help="IPA containing a SINF")
    license_group.add_argument("--sinf", type=Path, help="raw SINF")
    parser.add_argument("--sinf-member", help="IPA ZIP member when selectors differ")
    parser.add_argument("--output-dir", type=Path, help="new directory for credential.bin")
    parser.add_argument("--device-udid", help="connected device UDID")
    parser.add_argument("--ssh-port", type=int, default=2222, help="local USB SSH port (default: 2222)")
    args = parser.parse_args()
    if args.sinf_member and not args.ipa:
        parser.error("--sinf-member requires --ipa")
    if not args.output_dir or args.output_dir.exists():
        parser.error("--output-dir must name a new directory")
    sinf = license_sinf(args.sinf, args.ipa, args.sinf_member) if args.sinf or args.ipa else None
    udid = normalize_udid(args.device_udid) if args.device_udid else connected_udid()
    device = SSHDevice(args.ssh_port, udid)
    try:
        for name in DEVICE_FILES:
            device.write(name, args.bundle / name, executable=name.endswith(".ios"))
        program = device.path("credential.ios")
        actual_udid = device.path("device-udid.bin")
        device.run(" ".join(map(shlex.quote, (program, "device-udid", actual_udid))))
        if device.read(actual_udid) != bytes.fromhex(udid):
            raise ValueError("SSH tunnel is connected to a different device")
        installed_app, executable, installed_sinf = trigger_app(device, sinf)
        license_path = device.write("license.sinf", sinf if sinf is not None else installed_sinf)
        trigger_dir = device.trigger_directory
        device.run("cp -R " + shlex.quote(installed_app) + " " + shlex.quote(trigger_dir))
        unique_executable = str(Path(trigger_dir) / Path(installed_app).name / executable)
        uid_layer_path = device.path("uid-layer.bin")
        observe_uid_layer(device, program, restart_fairplayd(device), uid_layer_path, device.path("trigger.ios"), unique_executable)
        credential_path = device.path("credential.bin")
        device.run(" ".join(map(shlex.quote, (program, "retrieve", license_path, uid_layer_path, credential_path))))
        credential = device.read(credential_path)
    finally:
        device.cleanup()
    os.umask(0o077)
    args.output_dir.mkdir(parents=True, mode=0o700)
    write_new(args.output_dir / "credential.bin", credential)
    print(f"credential ready: {args.output_dir / 'credential.bin'}")


if __name__ == "__main__":
    main()
