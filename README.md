# IPA decryptor

Decrypt FairPlay-encrypted apps using a 16-byte credential
for the account that owns each IPA. [Credential retrieval](credential-retrieval/README.md)
gets it from a supported jailbroken device and writes
`credential.bin` to the chosen output directory.

Decryption runs on macOS and Linux.

Supports version-3 and version-5 SUPF, 448-byte and 440-byte SINF `priv`
records, and encrypted arm64 Mach-O slices. A 440-byte record must end in
eight zero bytes.

## Set up

From this directory, with Python 3.9+:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
```

The decryptor is pure Python. On macOS, `make` builds the
credential-retrieval bundle and requires Xcode and `ldid`.

## Decrypt

```sh
python decrypt.py /path/to/encrypted.ipa /path/to/decrypted.ipa \
  --credential /path/to/credential.bin
```

If `--credential` is omitted, the tool reads `./credential.bin`. The output
path must not exist.

By default, store metadata is removed from the output: `iTunesMetadata.plist`,
`iTunesArtwork`, and `META-INF/com.apple.*`. Pass `--keep-metadata` to keep them.

The decryptor uses each IPA's SINF and SUPF records to derive page keys,
decrypt its encrypted arm64 pages, and clear `cryptid`.
