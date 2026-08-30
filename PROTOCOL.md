# KeePass FIDO2 Unlock Protocol

This document defines the unlock-file and broker wire formats. Every version
field is encoded as the integer `1`.

## Unlock File

### Scope

The FIDO2 unlock file is attacker-controlled input. Readers fail closed before
any FIDO operation when a field, length, ordering rule, reserved byte, or file
boundary is invalid.

### Constants

```text
FIDO2 unlock file magic  ASCII "KPYKUNLK" (8 bytes)
wire version             1
fixed RP ID              ASCII "fido2-envelope.keepassxc.org" (28 bytes)
crypto AAD magic         ASCII "KPYKSID1" (8 bytes)
crypto version           1
maximum file size        65536 bytes
```

All integers are unsigned big-endian. `envelope-id`, `slot-id`, and
`credential-id` are raw bytes, not text encodings.

### Binary Wire Format

The file starts with this 94-byte header:

```text
magic                8 bytes   "KPYKUNLK"
wire-version         u16be     1
total-length         u32be     exact number of bytes in the complete file
envelope-id          16 bytes
rp-id                28 bytes  exact fixed RP ID constant
envelope-salt        32 bytes  raw CTAP hmac-secret salt
payload-policy       u8        1 = Password only, 2 = Password and key file
wrapper-count        u8        1 through 8
reserved             2 bytes   all zero
```

It is followed by exactly `wrapper-count` wrappers:

```text
slot-id               16 bytes
label-length          u8        1 through 128
label                 label-length bytes, strict UTF-8, no NUL
credential-id-length  u16be     1 through 1024
credential-id         credential-id-length bytes
public-key            64 bytes  P-256 affine X || Y, 32 bytes each
nonce                 12 bytes
ciphertext-and-tag    80 bytes  64-byte ciphertext || 16-byte GCM tag
uv-required           u8        0x01
reserved              3 bytes   all zero
```

Wrappers must be in strictly increasing lexicographic order by their raw
16-byte `slot-id`. This provides canonical ordering and rejects duplicate slot
IDs. Credential IDs must also be pairwise distinct. The parser must validate
every length before advancing, reject arithmetic overflow, require the header
length to equal the supplied file length, and require exact EOF after the final
wrapper. It rejects files over the file-size cap and rejects a `payload-policy`
other than `0x01` or `0x02` before any FIDO operation.

Each public key must decode as canonical affine X and Y field elements for
prime256v1 and satisfy that curve's equation. The point at infinity and any
off-curve or out-of-range coordinates are rejected during parsing before any
FIDO operation.

### Payload Policies

The payload policy is envelope-wide. Each wrapper encrypts a fixed 64-byte
logical payload under that policy:

```text
P = PasswordKey, exactly 32 raw bytes
F = FileKey, exactly 32 raw bytes
plaintext = P || F
```

Policy `0x01`, Password only, stores `P || zero[32]`. Writers set all 32 `F`
bytes to zero. After authenticated decryption, readers require all 32 bytes to
be zero or reject the FIDO2 unlock file. FIDO unlock reconstructs `P` plus any
externally selected native key file through the normal KeePassXC key-file path.

Policy `0x02`, Password and key file, stores `P || F`, where `F` is the exact
32-byte `FileKey::rawKey` value. FIDO unlock reconstructs `P` and `F` from the
FIDO2 unlock file and ignores any externally selected native key file. The
reconstructed CompositeKey contains `F` exactly once; a literal duplicate `F`
is forbidden.

### Cryptography

Each wrapper uses its own nonce and ciphertext while every wrapper in the
FIDO2 unlock file uses the one `envelope-salt` and `payload-policy` from the
header. `uv-required` is always `0x01`.

For a selected wrapper:

```text
AAD = ASCII("KPYKSID1")
   || u32be(1)
   || payload-policy
   || envelope-id
   || slot-id
   || u16be(length(fixed-rp-id)) || fixed-rp-id
   || u16be(length(credential-id)) || credential-id
   || public-key
   || envelope-salt
   || uv-required

IKM       = raw 32-byte hmac-secret assertion output
HKDF salt = envelope-id
HKDF info = ASCII("keepassxc-fido2-unlock-file-v1-kek") || slot-id
HKDF hash = SHA-256
HKDF L    = 32
KEK       = HKDF output

AEAD      = AES-256-GCM
nonce     = wrapper nonce, 12 bytes
plaintext = P || F, 64 bytes
tag       = 16 bytes, appended to ciphertext
```

The payload policy, RP ID, envelope ID, slot ID, credential ID, public key,
envelope salt, and UV policy are authenticated by AAD. Labels are public
display metadata and are not cryptographic inputs. The policy byte occurs
immediately after the four-byte crypto version; all other AAD and HKDF inputs
retain the ordering and semantics shown above.

### Lifecycle

Initial creation and explicit FIDO2 unlock file recreation generate a fresh
envelope ID, envelope salt, slot IDs, and wrapper nonces. Adding a wrapper to an
existing FIDO2 unlock file retains that FIDO2 unlock file's envelope ID,
envelope salt, and payload policy, creates a new slot ID and nonce, and rewrites
all wrappers in canonical slot-ID order.

### Broker Binding

Clients send the shared `envelope-salt` and all wrapper credential IDs through
the broker Assert request. The broker does not interpret the
payload policy. The selected credential ID returned by the broker must identify
exactly one wrapper in the parsed FIDO2 unlock file before its public key, nonce,
ciphertext, and AAD are used. Clients verify the assertion signature, RP hash,
client-data hash, UP, and UV before using the returned hmac-secret.

## Broker

### Process Model

The broker is a one-shot process launched from a fixed packaged path. It reads
one request frame from stdin through EOF, writes one response frame to stdout,
and exits. It accepts no command-line arguments. PIN and hmac-secret bytes are
carried only by anonymous pipes and must not be logged.

All integers are unsigned and big-endian. Every variable byte or UTF-8 field is
encoded as `u16 length || bytes`, except `credential-count`, which is one byte.
The maximum frame payload is 65536 bytes. Trailing transport or payload bytes
are rejected.

### Request Header

```text
magic          4 bytes   "KPYQ"
version        u16       1
operation      u16       1=create, 2=assert, 3=probe
payload-length u32
```

### Response Header

```text
magic          4 bytes   "KPYR"
version        u16       1
operation      u16       request operation, or 0 when undecodable
status         u16
reserved       u16       0
payload-length u32
```

An error payload is at most 256 bytes of UTF-8 diagnostic text and never
contains secret values.

### Probe

The request payload is exactly empty. The broker manifests connected devices,
requires exactly one, opens it, and validates FIDO2, PIN, and credProtect
support. Probe accepts no secrets and performs no touch, create, or assert
operation. The success payload is exactly empty.

### Create

Request payload:

```text
client-data-hash        32 bytes
rp-id                   28 bytes, exact ASCII "fido2-envelope.keepassxc.org"
rp-name                 UTF-8 bytes, at most 128, no NUL
user-id                 bytes, 1 through 64
user-name               UTF-8 bytes, at most 128, no NUL
user-display-name       UTF-8 bytes, at most 128, no NUL
PIN                     UTF-8 bytes, 4 through 63, no NUL
```

The operation creates a non-discoverable ES256 credential with `rk=false`,
hmac-secret, UP, UV, and `credProtect=userVerificationRequired`, then verifies
the attestation. The authenticator stores no per-credential resident record.
The returned credential ID is external state carried by the unlock file.

Success payload:

```text
credential-id           bytes, 1 through 1024
public-key              64 bytes, P-256 X || Y
flags                   u8
credential-protection   u8, value 3
```

### Assert

Request payload:

```text
client-data-hash        32 bytes
hmac-salt               32 bytes, raw CTAP salt
rp-id                   28 bytes, exact ASCII "fido2-envelope.keepassxc.org"
credential-count        u8, 1 through 8
credential-id           bytes, 1 through 1024, repeated credential-count times
PIN                     UTF-8 bytes, 4 through 63, no NUL
```

Credential IDs must be pairwise distinct. The operation requires exactly one
connected FIDO device, adds every supplied ID to the authenticator allow-list,
and forces UP and UV. The broker never retries a PIN automatically. It rejects
any result other than exactly one assertion with a non-empty selected credential
ID that is a member of the supplied allow-list.

Success payload:

```text
selected-credential-id  bytes, 1 through 1024
authenticator-data      bytes, 1 through 2048
DER ES256 signature     bytes, 1 through 256
raw hmac-secret         32 bytes
```

The selected credential ID is mandatory even when the allow-list contains one
ID.

### Linux Cancellation

The parent requests cancellation by sending `SIGUSR1` to the broker process. An
interrupted operation returns status `Cancelled`.

### Status Values

| Value | Name |
| ---: | --- |
| 0 | Ok |
| 1 | MalformedRequest |
| 2 | UnsupportedVersion |
| 3 | NoDevice |
| 4 | MultipleDevices |
| 5 | UnsupportedDevice |
| 6 | PinInvalid |
| 7 | PinBlocked |
| 8 | Timeout |
| 9 | Cancelled |
| 10 | Denied |
| 11 | NoCredential |
| 255 | Internal |
