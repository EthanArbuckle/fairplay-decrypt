# IPA decryptor

Decrypt FairPlay-encrypted apps using a 16-byte credential
for the account that owns each IPA. [Credential retrieval](credential-retrieval/README.md)
gets it from a supported jailbroken device and writes
`credential.bin` to the chosen output directory.

Decryption runs on macOS and Linux.

Supports version-3 and version-5 SUPF, 448-byte and 440-byte SINF `priv`
records, and encrypted arm64 Mach-O slices. A 440-byte record must end in
eight zero bytes.

## Prebuilt executables

[Releases](../../releases) provide single-file executables that need no
Python install:

- `fairplay-decrypt-{linux-x86_64,linux-arm64,macos-arm64}`: the decryptor.
- `fairplay-credential-macos-arm64`: credential retrieval, with the device
  bundle built in.

```sh
chmod +x fairplay-decrypt-macos-arm64
xattr -d com.apple.quarantine fairplay-decrypt-macos-arm64  # macOS only
./fairplay-decrypt-macos-arm64 encrypted.ipa decrypted.ipa --credential credential.bin
```

To build them locally, install `pyinstaller` and run `make dist`.

## Set up

From this directory, with Python 3.9+ and a C compiler:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
make
```

On macOS, `make` also builds the credential-retrieval bundle and requires
Xcode and `ldid`. On Linux, it builds the decryptor.

## Decrypt

```sh
python decrypt.py /path/to/encrypted.ipa /path/to/decrypted.ipa \
  --credential /path/to/credential.bin
```

If `--credential` is omitted, the tool reads `./credential.bin`. The output
path must not exist.

The decryptor uses each IPA's SINF and SUPF records to derive page keys,
decrypt its encrypted arm64 pages, and clear `cryptid`.
