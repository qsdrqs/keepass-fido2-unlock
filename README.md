# KeePass FIDO2 Unlock

This repository contains a portable FIDO2 unlock-file format, a one-shot Linux
libfido2 broker, an enrollment CLI, and Nix packaging for a KeePassXC client
that can consume the resulting unlock file.

## Disclaimer

Most of the code in this repository was generated and reviewed by AI systems.
It is provided as-is, without any guarantee of quality, correctness, security,
or fitness for a particular purpose. Review and test the code independently
before relying on it to protect sensitive data.

## Build

The flake locks nixpkgs independently from the host system and pins the reviewed
KeePassXC fork revision. Build the complete client with:

```bash
nix build path:.#keepassxc-fido2
```

Build only the broker:

```bash
nix build path:.#linux-libfido2
```

Build only the enrollment CLI:

```bash
nix build path:.#keepass-fido2-enroll
```

Run broker checks:

```bash
cd broker/linux-libfido2
nix develop path:../.. --command cargo test --locked
nix develop path:../.. --command cargo clippy --locked --all-targets -- -D warnings
```

The KeePassXC derivation enables its non-GUI test suite during `nix build`.

## Usage

The FIDO2 unlock file is a separate binary file from the KDBX. Connect exactly
one FIDO2 authenticator with a configured PIN and support for `hmac-secret` and
`credProtect`.

Create a password-only FIDO2 unlock file:

```bash
keepass-fido2-enroll create ~/Documents/personal.fido2 "primary-yubikey"
```

For a KDBX that uses a password and key file, include both components:

```bash
keepass-fido2-enroll create-with-key-file ~/Documents/personal.fido2 "primary-yubikey"
```

The CLI prompts for the database password, optional key-file path, FIDO2 PIN,
and touches. It does not read the KDBX and cannot validate those credentials.
In the modified KeePassXC, open the KDBX, click **Use FIDO2 to unlock**, select
the FIDO2 unlock file, enter the PIN, click **Unlock**, and touch the
authenticator. Verify the new enrollment immediately.

To add another authenticator, connect only that authenticator and run:

```bash
keepass-fido2-enroll append ~/Documents/personal.fido2 "backup-key"
```

List and remove enrolled wrappers:

```bash
keepass-fido2-enroll list ~/Documents/personal.fido2
keepass-fido2-enroll remove ~/Documents/personal.fido2 0123456789abcdef0123456789abcdef
```

Labels are human-readable and need not be unique. Use the stable slot ID printed
by `list` to select the exact wrapper for `remove`. After changing the KDBX
password or key file, create and verify a new FIDO2 unlock file.

## Architecture

Enrollment and unlock use the same one-shot broker but do not communicate with
each other directly:

```text
Enrollment CLI -> broker -> authenticator
Enrollment CLI <- hmac-secret and signed assertion
Enrollment CLI -> encrypt PasswordKey and optional FileKey -> unlock file

KeePassXC -> broker -> authenticator
KeePassXC <- hmac-secret and signed assertion
KeePassXC -> verify assertion -> decrypt wrapper -> CompositeKey -> KDBX
```

The broker is a short-lived libfido2 process launched from a fixed Nix store
path. It accepts one bounded binary request on stdin, writes one bounded binary
response on stdout, and exits. It receives the FIDO2 PIN but never receives the
database password, FileKey, KDBX contents, or encrypted wrapper.

During enrollment, the CLI computes `P = SHA-256(password)` and obtains the
authenticator's `hmac-secret` output through the broker. The output derives an
AES-256-GCM key that encrypts `P` and, when required, the native FileKey. During
unlock, KeePassXC obtains the same `hmac-secret`, independently verifies the
signed assertion, decrypts the wrapper in its own process, and reconstructs the
ordinary KeePass key components. The original password string is not recovered.

## Safety Boundary

The integration never writes FIDO2 metadata, credentials, or key changes
to a KDBX. The database keeps its existing password-only or password-and-key-
file credentials and continues to open with them in unmodified KeePassXC,
KeePassDX, and keepassxc-cli. The modified Linux client can instead use a
synchronized binary FIDO2 unlock file plus an enrolled authenticator, PIN, and touch
to recover the ordinary PasswordKey and, when selected by policy, the exact
FileKey raw key.

One FIDO2 unlock file contains independent wrappers for up to eight credentials.
Any enrolled authenticator can unlock independently. The unlock-file path may be
remembered in local KeePassXC configuration but is not stored in the file.

Each wrapper is enrolled independently. Supplying a wrong password or key file
while appending creates a stale wrapper without changing existing wrappers or
the KDBX. Verify every new wrapper immediately and re-enroll it if verification
fails.

Treat FIDO2 unlock files as untrusted synchronized input. Their confidentiality
is not a security prerequisite. Under the Password and key file policy, a
disclosed FIDO2 unlock file plus an enrolled authenticator and its PIN is a sufficient
credential set for a matching KDBX. Under the Password only policy, a database
that requires a native key file still requires that external file. A database
password or key file change makes current wrappers stale for the new KDBX as
applicable, while matching historical FIDO2 unlock file and KDBX copies remain
usable.

Enrollment creates non-discoverable credentials with `rk=false`. The
authenticator stores no per-credential resident record, and these credentials
consume no resident slots. The FIDO2 unlock file carries each credential ID so
the matching authenticator can reconstruct the credential. Removing the wrapper
or file removes that usable external state; there is no per-credential resident
object to delete.

Windows FIDO2 integration is not provided; ordinary password and key-file
unlock remains unchanged on unsupported clients.

The complete wire contract is defined in [`PROTOCOL.md`](PROTOCOL.md).
