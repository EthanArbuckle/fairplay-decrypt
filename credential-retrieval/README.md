# Credential retrieval

Retrieve a reusable 16-byte FairPlay account credential from a jailbroken
device. The host needs Python, `idevice_id`, `iproxy`, and USB SSH.

Supports iOS 10+.

## Retrieve

Connect one paired, jailbroken device with root SSH key access. Install at
least one App Store app on that device. From the project root:

```sh
make
python3 credential-retrieval/retrieve.py --output-dir /path/to/new-output-directory
```

The retriever uses the first installed app with a supported license. To
select a particular account, pass `--ipa /path/to/app.ipa` or
`--sinf /path/to/license.sinf`; an installed app under that account is still
required. If an IPA has distinct license selectors, specify one with
`--sinf-member`. Set `--ssh-port` if the USB SSH tunnel does not use port 2222.
The output directory must not exist; it receives `credential.bin` for use
with `decrypt.py --credential`.

## Apple Arcade

Apple Arcade apps need a different credential from regular App Store apps.
The normal credential decrypts regular apps, and the Arcade credential
decrypts Arcade apps. You need both to decrypt both types. Each credential
works with apps from the Apple Account it came from.

To retrieve an Arcade credential, pass an Arcade IPA with `--ipa` and have
an Arcade app from that account installed on the device.

Build on a Mac with Xcode and `ldid`.
