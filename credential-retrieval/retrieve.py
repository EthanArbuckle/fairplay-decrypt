"""Run the native credential retriever on a jailbroken device over USB SSH."""

from __future__ import annotations

import argparse
import os
import plistlib
import re
import select
import shlex
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from zipfile import ZipFile

from native_ssh import SSHDevice

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parent))
from core import derive_work16  # noqa: E402

BUNDLE = ROOT / "build" / "bundle"
DEVICE_FILES = (
    "credential.ios",
    "driver.ios",
    "trigger.ios",
    "arcade-capture.ios",
    "static-key-table.bin",
    "core4-word-table.bin",
)
MAX_SINF_BYTES = 1 << 20
SIDO_PATH = "/private/var/mobile/Library/FairPlay/iTunes_Control/iTunes/IC-Info.sido"
ARCADE_INVERSES = bytes(pow(2 * index + 1, -1, 256) for index in range(16))


def arcade_table_masks(image: bytes) -> list[bytes]:
    masks = []
    for offset in range(len(image) - 4096 + 1):
        delta = image[offset] ^ image[offset + 16]
        if (image[offset + 1] ^ image[offset + 17]) != delta or (
            image[offset + 2] ^ image[offset + 18]
        ) != delta:
            continue

        first = image[offset : offset + 16]
        if len(set(first)) < 8 or any(
            (image[offset + index] ^ image[offset + 16 + index]) != delta
            for index in range(3, 16)
        ):
            continue

        if all(
            all(
                (image[offset + row * 16 + index] ^ first[index])
                == (image[offset + row * 16] ^ first[0])
                for index in range(1, 16)
            )
            for row in range(2, 256)
        ):
            masks.append(bytes(value ^ first[0] for value in first))

    return masks


def arcade_credential(blocks: list[bytes], sinf: bytes, image: bytes) -> bytes:
    if len(blocks) != 3:
        raise ValueError("expected three Arcade block snapshots")

    masks = arcade_table_masks(image)
    if not masks:
        raise RuntimeError("no Arcade table masks found in fairplayd")

    for block in (blocks[1], blocks[0], blocks[2]):
        for relative in masks:
            for offset in range(len(block) - 15):
                for base in range(256):
                    candidate = bytes(
                        (
                            (
                                (
                                    block[offset + index]
                                    ^ relative[(offset + index) & 15]
                                    ^ base
                                )
                                - index
                            )
                            * ARCADE_INVERSES[index]
                            & 255
                        )
                        ^ 0x30
                        for index in range(16)
                    )
                    try:
                        derive_work16(candidate, sinf)
                    except ValueError:
                        continue

                    return candidate

    raise RuntimeError("no Arcade credential found in the captured blocks")


def connected_udid() -> str:
    devices = subprocess.run(
        ["idevice_id", "-l"], capture_output=True, text=True, check=True, timeout=10
    ).stdout.splitlines()
    if len(devices) != 1:
        raise RuntimeError(f"connect exactly one device; found {len(devices)}")
    return normalize_udid(devices[0])


def normalize_udid(value: str) -> str:
    value = value.strip().lower()
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{8}-[0-9a-f]{16})", value):
        raise ValueError("device UDID must be 40 hex digits or 8-16 hex digits")
    return value


def fairplay_device_id(value: str) -> bytes:
    """Keep USB identity separate from the 20-byte FairPlay identity.

    Modern format verified against iOS 16.3.1 fairplayd.H2's parser and
    its runtime output (new-format branch at image VA 0x1002789d4).
    """
    value = normalize_udid(value)
    if "-" in value:
        return bytes.fromhex("6097a4b0c20a0a9f" + value.replace("-", ""))
    return bytes.fromhex(value)


def children(data: bytes, start: int, end: int) -> Iterator[tuple[bytes, int, int]]:
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
    schi = [
        item for item in children(sinf, root[0][1], root[0][2]) if item[0] == b"schi"
    ]
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
        return (
            len(sinf_field(sinf, b"user")) == 4
            and len(sinf_field(sinf, b"key ")) == 4
            and len(sinf_field(sinf, b"iviv")) == 16
            and (len(priv) == 448 or (len(priv) == 440 and priv[-8:] == bytes(8)))
        )
    except ValueError:
        return False


def license_sinf(
    raw_path: Path | None, ipa_path: Path | None, member: str | None
) -> bytes:
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
            names = sorted(
                name
                for name in archive.namelist()
                if "/SC_Info/" in name
                and name.endswith(".sinf")
                and not name.endswith(".v4.sinf")
            )
            if member:
                if member not in names:
                    raise ValueError("--sinf-member is not a supported SINF")
                names = [member]
            selectors: dict[tuple[bytes, bytes], list[tuple[str, bytes]]] = {}
            for name in names:
                if archive.getinfo(name).file_size > MAX_SINF_BYTES:
                    continue
                candidate = archive.read(name)
                try:
                    if not supported_sinf(candidate):
                        continue
                    selector = (
                        sinf_field(candidate, b"user"),
                        sinf_field(candidate, b"key "),
                    )
                except ValueError:
                    continue
                selectors.setdefault(selector, []).append((name, candidate))
            if len(selectors) != 1:
                raise ValueError(
                    f"IPA has {len(selectors)} distinct license selectors; choose one with --sinf-member"
                )
            sinf = min(
                next(iter(selectors.values())),
                key=lambda item: (item[0].count("/"), item[0]),
            )[1]
    if len(sinf) > MAX_SINF_BYTES:
        raise ValueError("SINF is too large")
    list(children(sinf, 0, len(sinf)))
    if (
        len(sinf) < 8
        or sinf[4:8] != b"sinf"
        or int.from_bytes(sinf[:4], "big") != len(sinf)
    ):
        raise ValueError("expected one complete SINF atom")
    if not supported_sinf(sinf):
        raise ValueError("license format is not supported")
    return sinf


def write_new(path: Path, data: bytes) -> None:
    with os.fdopen(
        os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
    ) as stream:
        stream.write(data)


def trigger_app(
    device: SSHDevice, license_bytes: bytes | None
) -> tuple[str, str, bytes]:
    account = sinf_field(license_bytes, b"user") if license_bytes is not None else None
    key = sinf_field(license_bytes, b"key ") if license_bytes is not None else None
    arcade = key is not None and key[0] == 4
    fallback: tuple[str, str, bytes] | None = None
    listing = device.run(
        "find /var/containers/Bundle/Application -type f -path '*/SC_Info/*.sinf' -print0"
    )
    for raw_path in sorted(
        path for path in listing.split(b"\0") if path and not path.endswith(b".v4.sinf")
    ):
        path = raw_path.decode("utf-8", "surrogateescape")
        bundle = Path(path).parent.parent
        if bundle.suffix != ".app":
            continue
        try:
            installed_sinf = device.read(path)
            if len(installed_sinf) > MAX_SINF_BYTES or (
                account is not None and sinf_field(installed_sinf, b"user") != account
            ):
                continue
            installed_key = sinf_field(installed_sinf, b"key ")
            if len(installed_key) != 4:
                continue

            if arcade and installed_key[0] != 4:
                continue

            if license_bytes is None and not supported_sinf(installed_sinf):
                continue
            info = plistlib.loads(device.read(str(bundle / "Info.plist")))
            executable = info["CFBundleExecutable"]
            if (
                not isinstance(executable, str)
                or executable in ("", ".", "..")
                or "/" in executable
            ):
                continue
            candidate = str(bundle), executable, installed_sinf
            if key is None or installed_key == key:
                return candidate
            if fallback is None:
                fallback = candidate
        except (KeyError, ValueError, plistlib.InvalidFileException):
            continue
    if fallback is not None:
        return fallback
    raise RuntimeError(
        "no installed App Store app has a supported license for the selected account"
    )


def fairplayd_process(device: SSHDevice) -> tuple[int, str]:
    listing = device.processes().decode("utf-8", "replace")
    processes = []
    for line in listing.splitlines():
        fields = line.strip().split(None, 1)
        if (
            len(fields) == 2
            and fields[0].isdigit()
            and Path(fields[1]).name.split(".", 1)[0] == "fairplayd"
        ):
            processes.append((int(fields[0]), fields[1]))
    if len(processes) != 1:
        raise RuntimeError(f"expected one fairplayd process; found {len(processes)}")
    return processes[0]


def fairplayd_pid(device: SSHDevice) -> int:
    return fairplayd_process(device)[0]


def fairplayd_image(device: SSHDevice) -> bytes:
    path = fairplayd_process(device)[1]
    if not path.startswith("/"):
        path = "/usr/sbin/" + Path(path).name
    return device.read(path)


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
    listing = device.processes().decode("utf-8", "replace")
    result = []
    for line in listing.splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) == 2 and fields[0].isdigit() and fields[1] == executable:
            result.append(int(fields[0]))
    return result


def stop_remote(device: SSHDevice, executable: str) -> None:
    for pid in remote_pids(device, executable):
        device.run(f"kill -TERM {pid}")


def observe_uid_layer(
    device: SSHDevice,
    program: str,
    pid: int,
    output: str,
    trigger_program: str,
    executable: str,
    installed_executable: str | None = None,
    sido_path: str | None = None,
) -> None:
    arguments = (
        (program, str(pid), sido_path, output, "90")
        if sido_path is not None
        else (program, "observe-uid-layer", str(pid), output, "90")
    )
    command = " ".join(map(shlex.quote, arguments))
    observer = subprocess.Popen(
        device.command + [command], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    trigger_process = None
    direct_process = None
    try:
        stderr = observer.stderr
        if stderr is None:
            raise RuntimeError("FairPlay observer stderr unavailable")
        if not select.select([stderr], [], [], 15)[0]:
            raise RuntimeError("FairPlay observer did not become ready")
        ready = stderr.readline()
        if b"observing FairPlay " not in ready:
            raise RuntimeError(
                "FairPlay observer failed: " + ready.decode("utf-8", "replace")
            )
        trigger_command = " ".join(map(shlex.quote, (trigger_program, executable)))
        trigger_process = subprocess.Popen(
            device.command + [trigger_command],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        trigger_output, trigger_errors = trigger_process.communicate(timeout=15)
        if trigger_process.returncode:
            failure = trigger_output + trigger_errors
            if trigger_process.returncode != 3:
                raise RuntimeError(
                    "FairPlay trigger failed: " + failure.decode("utf-8", "replace")
                )
            direct_process = subprocess.Popen(
                device.command + [shlex.quote(executable)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        output_bytes, errors = observer.communicate(timeout=100)
        if observer.returncode:
            raise RuntimeError(
                "FairPlay observation failed: "
                + (output_bytes + errors).decode("utf-8", "replace")
            )
    finally:
        stop_remote(device, trigger_program)
        if installed_executable is not None:
            stop_remote(device, installed_executable)
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
    parser.add_argument(
        "--bundle",
        type=Path,
        default=BUNDLE,
        help="device bundle directory (default: credential-retrieval/build/bundle)",
    )
    license_group = parser.add_mutually_exclusive_group()
    license_group.add_argument("--ipa", type=Path, help="IPA containing a SINF")
    license_group.add_argument("--sinf", type=Path, help="raw SINF")
    parser.add_argument("--sinf-member", help="IPA ZIP member when selectors differ")
    parser.add_argument(
        "--output-dir", type=Path, help="new directory for credential.bin"
    )
    parser.add_argument("--device-udid", help="connected device UDID")
    parser.add_argument(
        "--ssh-port", type=int, default=2222, help="local USB SSH port (default: 2222)"
    )
    args = parser.parse_args()
    if args.sinf_member and not args.ipa:
        parser.error("--sinf-member requires --ipa")
    if not args.output_dir or args.output_dir.exists():
        parser.error("--output-dir must name a new directory")
    sinf = (
        license_sinf(args.sinf, args.ipa, args.sinf_member)
        if args.sinf or args.ipa
        else None
    )
    udid = normalize_udid(args.device_udid) if args.device_udid else connected_udid()
    device = SSHDevice(args.ssh_port, udid)
    try:
        for name in DEVICE_FILES:
            device.write(name, args.bundle / name, executable=name.endswith(".ios"))
        program = device.path("credential.ios")
        actual_udid = device.path("device-udid.bin")
        device.run(" ".join(map(shlex.quote, (program, "device-udid", actual_udid))))
        if device.read(actual_udid) != fairplay_device_id(udid):
            raise ValueError("SSH tunnel is connected to a different device")
        installed_app, executable, installed_sinf = trigger_app(device, sinf)
        selected_sinf = sinf if sinf is not None else installed_sinf
        arcade = sinf_field(selected_sinf, b"key ")[0] == 4
        daemon_image = fairplayd_image(device) if arcade else None
        license_path = device.write("license.sinf", selected_sinf)
        installed_executable = str(Path(installed_app) / executable)
        stop_remote(device, installed_executable)
        trigger_dir = device.trigger_directory
        device.run(
            "cp -R " + shlex.quote(installed_app) + " " + shlex.quote(trigger_dir)
        )
        unique_executable = str(
            Path(trigger_dir) / Path(installed_app).name / executable
        )
        uid_layer_path = device.path("uid-layer.bin")
        credential_path = device.path("credential.bin")
        arcade_prefix = device.path("arcade")
        observe_uid_layer(
            device,
            device.path("arcade-capture.ios") if arcade else program,
            restart_fairplayd(device),
            arcade_prefix if arcade else uid_layer_path,
            device.path("trigger.ios"),
            unique_executable,
            installed_executable,
            SIDO_PATH if arcade else None,
        )
        if arcade:
            if daemon_image is None:
                raise RuntimeError("fairplayd image is unavailable")
            credential = arcade_credential(
                [device.read(f"{arcade_prefix}.block{index}") for index in range(1, 4)],
                selected_sinf,
                daemon_image,
            )
        else:
            device.run(
                " ".join(
                    map(
                        shlex.quote,
                        (
                            program,
                            "retrieve",
                            license_path,
                            uid_layer_path,
                            credential_path,
                        ),
                    )
                )
            )
            credential = device.read(credential_path)
    finally:
        device.cleanup()
    os.umask(0o077)
    args.output_dir.mkdir(parents=True, mode=0o700)
    write_new(args.output_dir / "credential.bin", credential)
    print(f"credential ready: {args.output_dir / 'credential.bin'}")


if __name__ == "__main__":
    main()
