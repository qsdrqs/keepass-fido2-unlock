//! Bounded, platform-neutral A2 version 1 broker protocol.
//!
//! Request header: `KPYQ`, version (u16), operation (u16), payload length
//! (u32). Response header: `KPYR`, version (u16), operation (u16), status
//! (u16), reserved (u16), payload length (u32). Integers use network byte
//! order. A process accepts one frame followed by EOF; extra bytes fail closed.
//! Variable fields use a u16 length followed by bytes. PIN-bearing request and
//! hmac-secret-bearing response buffers are zeroized on drop.
//!
//! Decoding is split into transport framing, bounded field extraction, and
//! semantic validation. This keeps allocation limits independent of untrusted
//! lengths and ensures that a request is returned only after the entire frame,
//! including EOF, has been validated.

use std::fmt;
use std::io::{self, Read, Write};

use zeroize::Zeroizing;

const REQUEST_MAGIC: &[u8; 4] = b"KPYQ";
const RESPONSE_MAGIC: &[u8; 4] = b"KPYR";
const REQUEST_HEADER_SIZE: usize = 12;
const RESPONSE_HEADER_SIZE: usize = 16;
const MAX_PAYLOAD_SIZE: usize = 64 * 1024;
const MAX_NAME_SIZE: usize = 128;
const MAX_USER_ID_SIZE: usize = 64;
const MAX_CREDENTIAL_ID_SIZE: usize = 1024;
const MAX_CREDENTIAL_COUNT: usize = 8;
const MAX_AUTH_DATA_SIZE: usize = 2048;
const MAX_SIGNATURE_SIZE: usize = 256;
const MAX_PIN_SIZE: usize = 63;
const HASH_SIZE: usize = 32;
const ES256_PUBLIC_KEY_SIZE: usize = 64;
const RP_ID: &str = "fido2-envelope.keepassxc.org";

/// Protocol version encoded in every request and response header.
pub const VERSION: u16 = 1;

/// Operation code carried in a broker frame header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Operation {
    /// Create a new non-resident ES256 credential.
    Create = 1,
    /// Obtain an assertion and derive an hmac-secret value.
    Assert = 2,
    /// Check that exactly one suitable authenticator is available.
    Probe = 3,
}

impl TryFrom<u16> for Operation {
    type Error = DecodeError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Create),
            2 => Ok(Self::Assert),
            3 => Ok(Self::Probe),
            _ => Err(DecodeError::UnknownOperation(value)),
        }
    }
}

/// Stable status code carried in a response header.
///
/// Values through [`Status::NoCredential`] describe expected protocol or FIDO
/// outcomes. [`Status::Internal`] is the fail-closed fallback for library and
/// response failures that have no safe public classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum Status {
    /// The requested operation completed successfully.
    Ok = 0,
    /// The request frame or payload is not canonical or valid.
    MalformedRequest = 1,
    /// The request uses a protocol version this broker does not implement.
    UnsupportedVersion = 2,
    /// No authenticator is connected.
    NoDevice = 3,
    /// More than one authenticator is connected, so selection is ambiguous.
    MultipleDevices = 4,
    /// The authenticator lacks a capability required by the broker policy.
    UnsupportedDevice = 5,
    /// The supplied PIN is invalid.
    PinInvalid = 6,
    /// PIN or user-verification attempts are blocked.
    PinBlocked = 7,
    /// The authenticator operation exceeded its time limit.
    Timeout = 8,
    /// The caller or authenticator cancelled the operation.
    Cancelled = 9,
    /// The authenticator denied or disallowed the operation.
    Denied = 10,
    /// None of the allowed credentials is available on the authenticator.
    NoCredential = 11,
    /// An unclassified library, broker, or authenticator response failure.
    Internal = 255,
}

/// Validated payload for a credential-creation operation.
///
/// Instances returned by [`read_request`] satisfy all protocol field bounds,
/// contain the fixed relying-party ID, and keep the PIN in zeroizing storage.
pub struct CreateRequest {
    /// SHA-256 hash of the client data bound into the credential.
    pub client_data_hash: [u8; HASH_SIZE],
    /// Relying-party identifier, fixed by this protocol to the broker RP ID.
    pub rp_id: String,
    /// Human-readable relying-party name, bounded by [`MAX_NAME_SIZE`].
    pub rp_name: String,
    /// Non-empty opaque user handle, bounded by [`MAX_USER_ID_SIZE`].
    pub user_id: Vec<u8>,
    /// Account name shown by the authenticator, bounded by [`MAX_NAME_SIZE`].
    pub user_name: String,
    /// Display name shown by the authenticator, bounded by [`MAX_NAME_SIZE`].
    pub user_display_name: String,
    /// UTF-8 PIN of 4 through [`MAX_PIN_SIZE`] bytes, cleared when dropped.
    pub pin: Zeroizing<Vec<u8>>,
}

/// Validated payload for an assertion operation.
///
/// The credential allow-list is non-empty, contains no duplicates, and is
/// bounded in both entry count and encoded credential length.
pub struct AssertRequest {
    /// SHA-256 hash of the client data covered by the assertion signature.
    pub client_data_hash: [u8; HASH_SIZE],
    /// 32-byte salt supplied to the CTAP hmac-secret extension.
    pub hmac_salt: [u8; HASH_SIZE],
    /// Relying-party identifier, fixed by this protocol to the broker RP ID.
    pub rp_id: String,
    /// Distinct credential IDs bounded by count and encoded field length.
    pub credential_ids: Vec<Vec<u8>>,
    /// UTF-8 PIN of 4 through [`MAX_PIN_SIZE`] bytes, cleared when dropped.
    pub pin: Zeroizing<Vec<u8>>,
}

/// Fully decoded request selected by the frame operation code.
pub enum Request {
    /// Credential-creation request.
    Create(CreateRequest),
    /// Assertion and hmac-secret request.
    Assert(AssertRequest),
    /// Empty device-probe request.
    Probe,
}

impl Request {
    /// Returns the operation code corresponding to this decoded request.
    pub fn operation(&self) -> Operation {
        match self {
            Self::Create(_) => Operation::Create,
            Self::Assert(_) => Operation::Assert,
            Self::Probe => Operation::Probe,
        }
    }
}

/// Successful credential-creation payload returned by the FIDO layer.
pub struct CreateResponse {
    /// Non-empty credential identifier returned by the authenticator.
    pub credential_id: Vec<u8>,
    /// ES256 affine coordinates encoded as 32-byte X followed by 32-byte Y.
    pub public_key: [u8; ES256_PUBLIC_KEY_SIZE],
    /// Authenticator-data flags returned during credential creation.
    pub flags: u8,
    /// Applied CTAP credential-protection policy value.
    pub credential_protection: u8,
}

/// Successful assertion payload returned by the FIDO layer.
pub struct AssertResponse {
    /// Credential chosen by the authenticator from the request allow-list.
    pub selected_credential_id: Vec<u8>,
    /// Exact authenticator data bytes covered by the assertion signature.
    pub authenticator_data: Vec<u8>,
    /// Authenticator-provided assertion signature, bounded on serialization.
    pub signature: Vec<u8>,
    /// 32-byte hmac-secret extension output, cleared when dropped.
    pub hmac_secret: Zeroizing<[u8; HASH_SIZE]>,
}

/// Failure encountered while framing, decoding, or validating a request.
#[derive(Debug)]
pub enum DecodeError {
    /// Reading the transport failed or ended before a complete frame arrived.
    Io(io::Error),
    /// The request header does not begin with the request magic.
    InvalidMagic,
    /// The request names a protocol version not implemented by this broker.
    UnsupportedVersion(u16),
    /// The header contains an unknown operation code.
    UnknownOperation(u16),
    /// The declared payload exceeds the allocation bound.
    PayloadTooLarge,
    /// A payload field or cross-field invariant is invalid.
    Malformed(&'static str),
    /// Data follows the single declared request frame.
    TrailingData,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "I/O error: {error}"),
            Self::InvalidMagic => formatter.write_str("invalid request magic"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported protocol version {version}")
            }
            Self::UnknownOperation(operation) => write!(formatter, "unknown operation {operation}"),
            Self::PayloadTooLarge => formatter.write_str("request payload is too large"),
            Self::Malformed(message) => formatter.write_str(message),
            Self::TrailingData => formatter.write_str("trailing request data"),
        }
    }
}

impl From<io::Error> for DecodeError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Reads, decodes, and validates one bounded request frame.
///
/// EOF is required immediately after the declared payload, so concatenated or
/// padded requests are rejected rather than left for another consumer.
///
/// # Errors
///
/// Returns [`DecodeError`] for transport failures, invalid framing, fields that
/// exceed their protocol bounds, or request values that violate semantic
/// invariants.
pub fn read_request<R: Read>(mut input: R) -> Result<Request, DecodeError> {
    let mut header = [0u8; REQUEST_HEADER_SIZE];
    input.read_exact(&mut header)?;

    if &header[..4] != REQUEST_MAGIC {
        return Err(DecodeError::InvalidMagic);
    }

    let version = u16::from_be_bytes([header[4], header[5]]);
    if version != VERSION {
        return Err(DecodeError::UnsupportedVersion(version));
    }

    let operation = Operation::try_from(u16::from_be_bytes([header[6], header[7]]))?;
    let payload_size = u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;
    if payload_size > MAX_PAYLOAD_SIZE {
        return Err(DecodeError::PayloadTooLarge);
    }

    // The payload limit is checked before allocation. The entire PIN-bearing
    // frame remains in zeroizing storage while fields are copied out of it.
    let mut payload = Zeroizing::new(vec![0u8; payload_size]);
    input.read_exact(payload.as_mut_slice())?;

    let mut trailing = [0u8; 1];
    if input.read(&mut trailing)? != 0 {
        return Err(DecodeError::TrailingData);
    }

    let mut decoder = Decoder::new(payload.as_slice());
    let request = match operation {
        Operation::Create => Request::Create(CreateRequest {
            client_data_hash: decoder.fixed()?,
            rp_id: decoder.string(RP_ID.len(), "invalid RP ID")?,
            rp_name: decoder.string(MAX_NAME_SIZE, "invalid RP name")?,
            user_id: decoder.bytes(MAX_USER_ID_SIZE, "invalid user ID")?,
            user_name: decoder.string(MAX_NAME_SIZE, "invalid user name")?,
            user_display_name: decoder.string(MAX_NAME_SIZE, "invalid display name")?,
            pin: decoder.pin()?,
        }),
        Operation::Assert => Request::Assert(AssertRequest {
            client_data_hash: decoder.fixed()?,
            hmac_salt: decoder.fixed()?,
            rp_id: decoder.string(RP_ID.len(), "invalid RP ID")?,
            credential_ids: decoder.credential_ids()?,
            pin: decoder.pin()?,
        }),
        Operation::Probe => Request::Probe,
    };

    // No payload bytes may remain after the operation-specific field sequence.
    // Cross-field and fixed relying-party constraints are then checked on the
    // complete request rather than being spread across field extraction.
    decoder.finish()?;
    validate_request(&request)?;
    Ok(request)
}

/// Writes a successful create response using the version 1 canonical field order.
///
/// Variable-length fields are rejected if empty or outside their wire bounds.
pub fn write_create_response<W: Write>(output: W, response: &CreateResponse) -> io::Result<()> {
    let mut payload = Vec::new();
    encode_bytes(
        &mut payload,
        &response.credential_id,
        MAX_CREDENTIAL_ID_SIZE,
    )?;
    payload.extend_from_slice(&response.public_key);
    payload.push(response.flags);
    payload.push(response.credential_protection);
    write_frame(output, Operation::Create as u16, Status::Ok, &payload)
}

/// Writes a successful assertion response while zeroizing its encoded payload.
///
/// The temporary payload includes hmac-secret output and therefore remains in
/// zeroizing storage until the complete frame has been written.
pub fn write_assert_response<W: Write>(output: W, response: &AssertResponse) -> io::Result<()> {
    let mut payload = Zeroizing::new(Vec::new());
    encode_bytes(
        &mut payload,
        &response.selected_credential_id,
        MAX_CREDENTIAL_ID_SIZE,
    )?;
    encode_bytes(
        &mut payload,
        &response.authenticator_data,
        MAX_AUTH_DATA_SIZE,
    )?;
    encode_bytes(&mut payload, &response.signature, MAX_SIGNATURE_SIZE)?;
    payload.extend_from_slice(response.hmac_secret.as_ref());
    write_frame(output, Operation::Assert as u16, Status::Ok, &payload)
}

/// Writes the canonical empty successful probe response.
pub fn write_probe_response<W: Write>(output: W) -> io::Result<()> {
    write_frame(output, Operation::Probe as u16, Status::Ok, &[])
}

/// Writes a bounded diagnostic response for a broker status.
///
/// An unknown operation is encoded as zero. Diagnostic text is opaque bytes on
/// the wire and is truncated to 256 bytes to keep error frames small.
pub fn write_error<W: Write>(
    output: W,
    operation: Option<Operation>,
    status: Status,
    message: &str,
) -> io::Result<()> {
    let message = message.as_bytes();
    let message = &message[..message.len().min(256)];
    write_frame(
        output,
        operation.map_or(0, |value| value as u16),
        status,
        message,
    )
}

/// Writes one canonical bounded response frame and flushes the output.
fn write_frame<W: Write>(
    mut output: W,
    operation: u16,
    status: Status,
    payload: &[u8],
) -> io::Result<()> {
    if payload.len() > MAX_PAYLOAD_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "response payload is too large",
        ));
    }

    // Zero initialization keeps the reserved response-header field canonical.
    // The payload bound above also makes the conversion to u32 lossless.
    let mut header = [0u8; RESPONSE_HEADER_SIZE];
    header[..4].copy_from_slice(RESPONSE_MAGIC);
    header[4..6].copy_from_slice(&VERSION.to_be_bytes());
    header[6..8].copy_from_slice(&operation.to_be_bytes());
    header[8..10].copy_from_slice(&(status as u16).to_be_bytes());
    header[12..16].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    output.write_all(&header)?;
    output.write_all(payload)?;
    output.flush()
}

/// Appends a non-empty u16-length-prefixed byte string within `maximum`.
fn encode_bytes(output: &mut Vec<u8>, value: &[u8], maximum: usize) -> io::Result<()> {
    // Every encoded byte string is non-empty and must satisfy both its semantic
    // field bound and the u16 length-prefix bound.
    if value.is_empty() || value.len() > maximum || value.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid response field length",
        ));
    }
    output.extend_from_slice(&(value.len() as u16).to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

/// Validates invariants that depend on complete fields or multiple fields.
fn validate_request(request: &Request) -> Result<(), DecodeError> {
    let rp_id = match request {
        Request::Create(request) => {
            if request.user_id.is_empty() {
                return Err(DecodeError::Malformed("user ID must not be empty"));
            }
            &request.rp_id
        }
        Request::Assert(request) => {
            if request.credential_ids.is_empty()
                || request.credential_ids.len() > MAX_CREDENTIAL_COUNT
            {
                return Err(DecodeError::Malformed("invalid credential count"));
            }

            if request
                .credential_ids
                .iter()
                .any(|credential_id| credential_id.is_empty())
            {
                return Err(DecodeError::Malformed("credential ID must not be empty"));
            }

            for (index, credential_id) in request.credential_ids.iter().enumerate() {
                if request.credential_ids[..index].contains(credential_id) {
                    return Err(DecodeError::Malformed("duplicate credential ID"));
                }
            }
            &request.rp_id
        }
        Request::Probe => return Ok(()),
    };

    if rp_id != RP_ID {
        return Err(DecodeError::Malformed("unexpected RP ID"));
    }

    Ok(())
}

/// Forward-only decoder over one already-bounded payload.
///
/// Every read advances the cursor only after the complete field is available,
/// and [`Decoder::finish`] enforces exact consumption of the payload.
struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn fixed<const SIZE: usize>(&mut self) -> Result<[u8; SIZE], DecodeError> {
        let bytes = self.take(SIZE)?;
        let mut value = [0u8; SIZE];
        value.copy_from_slice(bytes);
        Ok(value)
    }

    fn bytes(&mut self, maximum: usize, message: &'static str) -> Result<Vec<u8>, DecodeError> {
        let size = self.u16()? as usize;
        if size > maximum {
            return Err(DecodeError::Malformed(message));
        }

        // Empty fields are decoded here and rejected by the relevant semantic
        // validator when the protocol requires a value.
        Ok(self.take(size)?.to_vec())
    }

    fn string(&mut self, maximum: usize, message: &'static str) -> Result<String, DecodeError> {
        let bytes = self.bytes(maximum, message)?;
        if bytes.contains(&0) {
            return Err(DecodeError::Malformed(message));
        }
        String::from_utf8(bytes).map_err(|_| DecodeError::Malformed(message))
    }

    fn pin(&mut self) -> Result<Zeroizing<Vec<u8>>, DecodeError> {
        let pin = Zeroizing::new(self.bytes(MAX_PIN_SIZE, "invalid PIN")?);
        if pin.len() < 4 || pin.contains(&0) || std::str::from_utf8(&pin).is_err() {
            return Err(DecodeError::Malformed("invalid PIN"));
        }

        Ok(pin)
    }

    fn credential_ids(&mut self) -> Result<Vec<Vec<u8>>, DecodeError> {
        let count = self.u8()? as usize;
        if !(1..=MAX_CREDENTIAL_COUNT).contains(&count) {
            return Err(DecodeError::Malformed("invalid credential count"));
        }

        let mut credential_ids = Vec::with_capacity(count);
        for _ in 0..count {
            credential_ids.push(self.bytes(MAX_CREDENTIAL_ID_SIZE, "invalid credential ID")?);
        }

        Ok(credential_ids)
    }

    fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, DecodeError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn take(&mut self, size: usize) -> Result<&'a [u8], DecodeError> {
        // Checked arithmetic and slice lookup jointly prevent a length prefix
        // from wrapping the cursor or reading beyond the bounded payload.
        let end = self
            .offset
            .checked_add(size)
            .ok_or(DecodeError::Malformed("invalid field length"))?;
        let bytes = self
            .input
            .get(self.offset..end)
            .ok_or(DecodeError::Malformed("truncated request payload"))?;
        self.offset = end;
        Ok(bytes)
    }

    fn finish(self) -> Result<(), DecodeError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(DecodeError::Malformed("trailing payload data"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const TEST_PIN: &[u8] = b"1234";
    const TEST_CREDENTIAL: &[u8] = b"credential";
    const TEST_CREDENTIAL_TWO: &[u8] = b"credential-two";
    const TEST_HMAC_SECRET: [u8; HASH_SIZE] = [3u8; HASH_SIZE];

    fn push_bytes(output: &mut Vec<u8>, value: &[u8]) {
        output.extend_from_slice(&(value.len() as u16).to_be_bytes());
        output.extend_from_slice(value);
    }

    fn request_frame(operation: Operation, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::from(REQUEST_MAGIC.as_slice());
        frame.extend_from_slice(&VERSION.to_be_bytes());
        frame.extend_from_slice(&(operation as u16).to_be_bytes());
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    fn assert_request_payload(rp_id: &[u8], credential_ids: &[&[u8]]) -> Vec<u8> {
        let mut payload = Vec::from([2u8; HASH_SIZE]);
        payload.extend_from_slice(&[3u8; HASH_SIZE]);
        push_bytes(&mut payload, rp_id);
        payload.push(credential_ids.len() as u8);
        for credential_id in credential_ids {
            push_bytes(&mut payload, credential_id);
        }
        push_bytes(&mut payload, TEST_PIN);
        payload
    }

    #[test]
    fn decodes_create_request() {
        let mut payload = Vec::from([1u8; HASH_SIZE]);
        push_bytes(&mut payload, RP_ID.as_bytes());
        push_bytes(&mut payload, b"KeePass YubiKey");
        push_bytes(&mut payload, b"user-id");
        push_bytes(&mut payload, b"user");
        push_bytes(&mut payload, b"User");
        push_bytes(&mut payload, TEST_PIN);

        let request =
            read_request(Cursor::new(request_frame(Operation::Create, &payload))).unwrap();
        let Request::Create(request) = request else {
            panic!("unexpected request type");
        };
        assert_eq!(request.client_data_hash, [1u8; HASH_SIZE]);
        assert_eq!(request.rp_id, RP_ID);
        assert_eq!(request.pin.as_slice(), TEST_PIN);
    }

    #[test]
    fn decodes_assert_request() {
        let payload =
            assert_request_payload(RP_ID.as_bytes(), &[TEST_CREDENTIAL, TEST_CREDENTIAL_TWO]);

        let request =
            read_request(Cursor::new(request_frame(Operation::Assert, &payload))).unwrap();
        let Request::Assert(request) = request else {
            panic!("unexpected request type");
        };
        assert_eq!(request.client_data_hash, [2u8; HASH_SIZE]);
        assert_eq!(request.hmac_salt, [3u8; HASH_SIZE]);
        assert_eq!(
            request.credential_ids,
            vec![TEST_CREDENTIAL.to_vec(), TEST_CREDENTIAL_TWO.to_vec()]
        );
    }

    #[test]
    fn decodes_empty_probe_request() {
        let request = read_request(Cursor::new(request_frame(Operation::Probe, &[]))).unwrap();

        assert!(matches!(&request, Request::Probe));
        assert_eq!(request.operation(), Operation::Probe);
    }

    #[test]
    fn rejects_non_empty_probe_request() {
        assert!(matches!(
            read_request(Cursor::new(request_frame(Operation::Probe, &[0]))),
            Err(DecodeError::Malformed("trailing payload data"))
        ));
    }

    #[test]
    fn rejects_trailing_transport_data() {
        let payload = assert_request_payload(RP_ID.as_bytes(), &[TEST_CREDENTIAL]);
        let mut frame = request_frame(Operation::Assert, &payload);
        frame.push(0);

        assert!(matches!(
            read_request(Cursor::new(frame)),
            Err(DecodeError::TrailingData)
        ));
    }

    #[test]
    fn encodes_error_response() {
        let mut response = Vec::new();
        write_error(
            &mut response,
            Some(Operation::Create),
            Status::NoDevice,
            "no device",
        )
        .unwrap();

        assert_eq!(&response[..4], RESPONSE_MAGIC);
        assert_eq!(u16::from_be_bytes([response[4], response[5]]), VERSION);
        assert_eq!(
            u16::from_be_bytes([response[8], response[9]]),
            Status::NoDevice as u16
        );
        assert_eq!(&response[RESPONSE_HEADER_SIZE..], b"no device");
    }

    #[test]
    fn encodes_empty_probe_success_response() {
        let mut response = Vec::new();
        write_probe_response(&mut response).unwrap();

        assert_eq!(&response[..4], RESPONSE_MAGIC);
        assert_eq!(u16::from_be_bytes([response[6], response[7]]), 3);
        assert_eq!(u32::from_be_bytes(response[12..16].try_into().unwrap()), 0);
        assert_eq!(response.len(), RESPONSE_HEADER_SIZE);
    }

    #[test]
    fn rejects_duplicate_assert_credential_ids() {
        let payload = assert_request_payload(RP_ID.as_bytes(), &[TEST_CREDENTIAL, TEST_CREDENTIAL]);

        assert!(matches!(
            read_request(Cursor::new(request_frame(Operation::Assert, &payload))),
            Err(DecodeError::Malformed("duplicate credential ID"))
        ));
    }

    #[test]
    fn rejects_empty_assert_credential_list() {
        let payload = assert_request_payload(RP_ID.as_bytes(), &[]);

        assert!(matches!(
            read_request(Cursor::new(request_frame(Operation::Assert, &payload))),
            Err(DecodeError::Malformed("invalid credential count"))
        ));
    }

    #[test]
    fn rejects_assert_credential_list_larger_than_eight() {
        let mut payload = Vec::from([2u8; HASH_SIZE]);
        payload.extend_from_slice(&[3u8; HASH_SIZE]);
        push_bytes(&mut payload, RP_ID.as_bytes());
        payload.push(9);
        for index in 0u8..9 {
            push_bytes(&mut payload, &[index]);
        }
        push_bytes(&mut payload, TEST_PIN);

        assert!(matches!(
            read_request(Cursor::new(request_frame(Operation::Assert, &payload))),
            Err(DecodeError::Malformed("invalid credential count"))
        ));
    }

    #[test]
    fn accepts_eight_assert_credential_ids() {
        let mut payload = Vec::from([2u8; HASH_SIZE]);
        payload.extend_from_slice(&[3u8; HASH_SIZE]);
        push_bytes(&mut payload, RP_ID.as_bytes());
        payload.push(8);
        for index in 0u8..8 {
            push_bytes(&mut payload, &[index]);
        }
        push_bytes(&mut payload, TEST_PIN);

        let request =
            read_request(Cursor::new(request_frame(Operation::Assert, &payload))).unwrap();
        let Request::Assert(request) = request else {
            panic!("unexpected request type");
        };
        assert_eq!(request.credential_ids.len(), 8);
    }

    #[test]
    fn rejects_unsupported_frame_version() {
        let mut frame = request_frame(Operation::Create, &[]);
        frame[4..6].copy_from_slice(&2u16.to_be_bytes());

        assert!(matches!(
            read_request(Cursor::new(frame)),
            Err(DecodeError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn rejects_non_fixed_rp_id_for_create() {
        let mut payload = Vec::from([1u8; HASH_SIZE]);
        push_bytes(&mut payload, b"other.invalid");
        push_bytes(&mut payload, b"KeePass YubiKey");
        push_bytes(&mut payload, b"user-id");
        push_bytes(&mut payload, b"user");
        push_bytes(&mut payload, b"User");
        push_bytes(&mut payload, TEST_PIN);

        assert!(matches!(
            read_request(Cursor::new(request_frame(Operation::Create, &payload))),
            Err(DecodeError::Malformed("unexpected RP ID"))
        ));
    }

    #[test]
    fn rejects_non_fixed_rp_id_for_assert() {
        let payload = assert_request_payload(b"other.invalid", &[TEST_CREDENTIAL]);

        assert!(matches!(
            read_request(Cursor::new(request_frame(Operation::Assert, &payload))),
            Err(DecodeError::Malformed("unexpected RP ID"))
        ));
    }

    #[test]
    fn rejects_empty_assert_credential_id() {
        let payload = assert_request_payload(RP_ID.as_bytes(), &[b""]);

        assert!(matches!(
            read_request(Cursor::new(request_frame(Operation::Assert, &payload))),
            Err(DecodeError::Malformed("credential ID must not be empty"))
        ));
    }

    #[test]
    fn rejects_oversized_assert_credential_id() {
        let oversized_credential = [0u8; MAX_CREDENTIAL_ID_SIZE + 1];
        let payload = assert_request_payload(RP_ID.as_bytes(), &[&oversized_credential]);

        assert!(matches!(
            read_request(Cursor::new(request_frame(Operation::Assert, &payload))),
            Err(DecodeError::Malformed("invalid credential ID"))
        ));
    }

    #[test]
    fn encodes_selected_credential_id_in_assert_response() {
        let response = AssertResponse {
            selected_credential_id: b"credential-two".to_vec(),
            authenticator_data: vec![1u8; 37],
            signature: vec![2u8; 70],
            hmac_secret: Zeroizing::new(TEST_HMAC_SECRET),
        };
        let mut encoded = Vec::new();

        write_assert_response(&mut encoded, &response).unwrap();

        let payload = &encoded[RESPONSE_HEADER_SIZE..];
        assert_eq!(&payload[..2], &(14u16).to_be_bytes());
        assert_eq!(&payload[2..16], b"credential-two");
    }

    #[test]
    fn rejects_assert_response_without_selected_credential_id() {
        let response = AssertResponse {
            selected_credential_id: Vec::new(),
            authenticator_data: vec![1u8; 37],
            signature: vec![2u8; 70],
            hmac_secret: Zeroizing::new(TEST_HMAC_SECRET),
        };

        assert!(write_assert_response(Vec::new(), &response).is_err());
    }
}
