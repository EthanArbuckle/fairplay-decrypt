# Credential retrieval

Retrieve a reusable 16-byte FairPlay account credential from a jailbroken
device. The host needs Python, `idevice_id`, `iproxy`, and USB SSH. The device
runs native programs only; it does not need Python or Frida.

Tested on iOS 14, iOS 15, iOS 16.6 (iPhone X, Dopamine with RootHide) and iOS 18.

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

Build on a Mac with Xcode and `ldid`.

## RootHide

RootHide-based jailbreaks are detected automatically through `jbroot`; no
additional options are needed. The retriever resolves its temporary directories
to physical paths so the bootstrap shell and native programs access the same
files. Process enumeration uses `/rootfs/bin/ps`, which is outside the
bootstrap's virtual filesystem.
