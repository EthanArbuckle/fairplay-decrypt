"""Device-free regression coverage for installed license selection."""

import plistlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import retrieve


def atom(tag: bytes, payload: bytes) -> bytes:
    return (len(payload) + 8).to_bytes(4, "big") + tag + payload


def sinf(account: bytes, key: bytes, name: bytes = b"app") -> bytes:
    return atom(
        b"sinf",
        atom(
            b"schi",
            atom(b"user", account)
            + atom(b"key ", key)
            + atom(b"name", name)
            + atom(b"iviv", bytes(16))
            + atom(b"priv", bytes(448)),
        ),
    )


class InstalledLicenseTests(unittest.TestCase):
    def test_matches_both_account_and_key(self) -> None:
        selected = sinf(b"user", b"key1")
        installed = sinf(b"user", b"key1", b"installed")
        paths = [f"/Apps/{name}.app/SC_Info/app.sinf" for name in ("A", "B", "C")]
        files = dict(
            zip(paths, (sinf(b"user", b"key2"), sinf(b"else", b"key1"), installed))
        )
        files["/Apps/C.app/Info.plist"] = plistlib.dumps({"CFBundleExecutable": "C"})
        device = MagicMock()
        device.run.return_value = b"\0".join(path.encode() for path in reversed(paths))
        device.read.side_effect = files.__getitem__

        self.assertEqual(
            retrieve.trigger_app(device, selected), ("/Apps/C.app", "C", installed)
        )
        device.read.assert_any_call(paths[0])
        device.read.assert_any_call(paths[1])

    def test_rejects_account_match_without_key_match(self) -> None:
        device = MagicMock()
        device.run.return_value = b"/Apps/A.app/SC_Info/app.sinf\0"
        device.read.return_value = sinf(b"user", b"key2")

        with self.assertRaises(RuntimeError):
            retrieve.trigger_app(device, sinf(b"user", b"key1"))

    def test_main_uses_installed_sinf(self) -> None:
        selected = sinf(b"user", b"key1", b"external")
        installed = sinf(b"user", b"key1", b"installed")
        udid = "a" * 40
        device = MagicMock()
        device.path.side_effect = lambda name: "/device/" + name
        device.read.side_effect = [bytes.fromhex(udid), bytes(16)]
        device.trigger_directory = "/trigger"
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            argv = [
                "retrieve.py",
                "--sinf",
                "external.sinf",
                "--device-udid",
                udid,
                "--output-dir",
                str(output),
            ]
            with (
                patch("sys.argv", argv),
                patch.object(retrieve, "license_sinf", return_value=selected),
                patch.object(retrieve, "SSHDevice", return_value=device),
                patch.object(
                    retrieve,
                    "trigger_app",
                    return_value=("/Apps/C.app", "C", installed),
                ) as trigger,
                patch.object(retrieve, "restart_fairplayd", return_value=1),
                patch.object(retrieve, "observe_uid_layer"),
                patch.object(retrieve.os, "umask"),
                patch.object(retrieve, "write_new"),
                patch("builtins.print"),
            ):
                retrieve.main()

        trigger.assert_called_once_with(device, selected)
        device.write.assert_any_call("license.sinf", installed)
        self.assertNotIn(
            call("license.sinf", selected), device.write.call_args_list
        )
        device.cleanup.assert_called_once_with()
