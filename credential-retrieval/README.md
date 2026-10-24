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

Sometimes the script has issues starting the iproxy tunnel. You can launch it
yourself in another terminal window.

For password auth, pass `--ssh-user` and `--ssh-password`. This needs `sshpass`
in `PATH`. This is useful for those on rootless jailbreaks like Dopamine.

```sh
python3 credential-retrieval/retrieve.py --ssh-user mobile --ssh-password alpine --output-dir /path/to/new-output-directory
```

Build on a Mac with Xcode and `ldid`.
