//! FIDO2 credential enrollment and canonical unlock-file management.
//!
//! This crate validates untrusted broker and file input, derives encrypted wrapper
//! payloads compatible with KeePassXC, and publishes updates through bounded,
//! symlink-resistant file operations.

use openssl::{
    base64,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::{Hasher, MessageDigest, hash},
    nid::Nid,
    pkey::{PKey, Public},
    rand::rand_bytes,
    sha::sha256,
    sign::{Signer, Verifier},
    symm::{Cipher, Crypter, Mode},
};
use quick_xml::{XmlVersion, encoding::DecodingReader, events::Event, reader::Reader};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{BufReader, Read, Seek, SeekFrom, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
};
use zeroize::{Zeroize, Zeroizing};

/// Fixed relying-party ID bound into credentials and FIDO2 unlock file authentication.
pub const RP_ID: &[u8] = b"fido2-envelope.keepassxc.org";
/// User-facing reminder required after FIDO2 unlock file publication.
pub const VERIFICATION_INSTRUCTION: &str = "FIDO2 unlock file published. Verify immediately by unlocking the database in the modified KeePassXC.";
const UNLOCK_FILE_MAGIC: &[u8] = b"KPYKUNLK";
const AAD_MAGIC: &[u8] = b"KPYKSID1";
const BROKER_REQUEST_MAGIC: &[u8; 4] = b"KPYQ";
const BROKER_RESPONSE_MAGIC: &[u8; 4] = b"KPYR";
const UNLOCK_FILE_VERSION: u16 = 1;
const AAD_VERSION: u32 = 1;
const BROKER_PROTOCOL_VERSION: u16 = 1;
const BROKER_CREATE_OPERATION: u16 = 1;
const BROKER_ASSERT_OPERATION: u16 = 2;
const BROKER_PROBE_OPERATION: u16 = 3;
const CREATE_TOUCH_INSTRUCTION: &str = "Touch the FIDO2 security key to create the credential.";
const ASSERT_TOUCH_INSTRUCTION: &str = "Touch the FIDO2 security key to verify the credential.";
const BROKER_REQUEST_HEADER_LEN: usize = 12;
const BROKER_RESPONSE_HEADER_LEN: usize = 16;
const MAX_BROKER_PAYLOAD: usize = 65_536;
const MAX_BROKER_RESPONSE: usize = BROKER_RESPONSE_HEADER_LEN + MAX_BROKER_PAYLOAD;
const AUTH_DATA_USER_PRESENT: u8 = 0x01;
const AUTH_DATA_USER_VERIFIED: u8 = 0x04;
const REQUIRED_AUTH_DATA_FLAGS: u8 = AUTH_DATA_USER_PRESENT | AUTH_DATA_USER_VERIFIED;
const CREDENTIAL_PROTECTION_UV_REQUIRED: u8 = 3;
const WRAPPER_UV_POLICY_REQUIRED: u8 = 1;
const HKDF_FIRST_BLOCK: u8 = 1;
const HEADER_LEN: usize = 94;
const MAX_FILE: usize = 65_536;
const MAX_WRAPPERS: usize = 8;
const BROKER_PATH: Option<&str> = option_env!("KEEPASS_FIDO2_BROKER_PATH");

/// Result type used by enrollment and file-format operations.
pub type Result<T> = std::result::Result<T, String>;

/// Selects which KeePassXC composite-key components a wrapper carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum PayloadPolicy {
    /// Store a PasswordKey and an all-zero FileKey.
    PasswordOnly = 1,
    /// Store both a PasswordKey and a FileKey.
    PasswordAndKeyFile = 2,
}

impl TryFrom<u8> for PayloadPolicy {
    type Error = String;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::PasswordOnly),
            2 => Ok(Self::PasswordAndKeyFile),
            _ => Err("FIDO2 unlock file payload policy is invalid".into()),
        }
    }
}

/// Canonical FIDO2 unlock file entry binding one credential to an encrypted key payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Wrapper {
    /// Unique wrapper identifier and canonical sort key.
    pub slot_id: [u8; 16],
    /// User-visible UTF-8 label.
    pub label: String,
    /// Opaque FIDO2 credential identifier.
    pub credential_id: Vec<u8>,
    /// P-256 public key encoded as fixed-width X followed by Y.
    pub public_key: [u8; 64],
    /// AES-256-GCM nonce for the encrypted key payload.
    pub nonce: [u8; 12],
    /// Encrypted 64-byte payload followed by its 16-byte GCM tag.
    pub ciphertext: [u8; 80],
}

/// Version 1 envelope metadata and its canonically ordered wrappers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fido2UnlockFile {
    /// Random identifier used as the wrapper-key derivation salt.
    pub envelope_id: [u8; 16],
    /// Shared salt supplied to the FIDO2 hmac-secret extension.
    pub envelope_salt: [u8; 32],
    /// Composite-key components encrypted by every wrapper.
    pub payload_policy: PayloadPolicy,
    /// Wrappers in strictly increasing raw slot-ID order.
    pub wrappers: Vec<Wrapper>,
}

/// Serializes cooperative CLI updates and detects path changes before publication.
/// The final pre-commit check is not an atomic compare-and-swap with the rename.
pub struct LockedFido2UnlockFileUpdate {
    path: PathBuf,
    _locked_file: File,
    original: Zeroizing<Vec<u8>>,
    device: u64,
    inode: u64,
    unlock_file: Fido2UnlockFile,
}

impl LockedFido2UnlockFileUpdate {
    /// Opens, exclusively locks, snapshots, and parses an existing unlock file.
    ///
    /// The advisory lock serializes cooperating CLI writers. Publication also
    /// rechecks file identity and content to detect non-cooperating changes.
    pub fn open(path: &Path) -> Result<Self> {
        let (mut file, metadata) = open_unlock_file(path)?;
        // Hold the advisory lock from the initial snapshot through any eventual
        // publication so cooperating writers cannot interleave their updates.
        loop {
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(format!(
                    "could not lock FIDO2 unlock file for update: {error}"
                ));
            }
        }
        let original = read_limited(&mut file, MAX_FILE, "FIDO2 unlock file")?;
        let unlock_file = parse_unlock_file(&original)?;
        Ok(Self {
            path: path.to_path_buf(),
            _locked_file: file,
            original,
            device: metadata.dev(),
            inode: metadata.ino(),
            unlock_file,
        })
    }

    /// Returns the parsed snapshot currently staged by this update.
    pub fn unlock_file(&self) -> &Fido2UnlockFile {
        &self.unlock_file
    }

    /// Returns the parsed snapshot for in-place mutation before commit.
    pub fn unlock_file_mut(&mut self) -> &mut Fido2UnlockFile {
        &mut self.unlock_file
    }

    /// Replaces the staged value while retaining the original lock and snapshot.
    pub fn set_unlock_file(&mut self, unlock_file: Fido2UnlockFile) {
        self.unlock_file = unlock_file;
    }

    /// Rechecks the locked path and atomically publishes the staged update.
    pub fn commit(self) -> Result<()> {
        let data = serialize_unlock_file(&self.unlock_file)?;

        // The advisory lock covers cooperative writers. Identity and byte-for-byte
        // content checks reject replacement or modification by other writers.
        let (current_file, metadata) = open_unlock_file(&self.path).map_err(|_| {
            "FIDO2 unlock file update conflict: path changed before publication".to_string()
        })?;
        if metadata.dev() != self.device || metadata.ino() != self.inode {
            return Err(
                "FIDO2 unlock file update conflict: file was replaced before publication".into(),
            );
        }
        let current = read_limited(current_file, MAX_FILE, "FIDO2 unlock file").map_err(|_| {
            "FIDO2 unlock file update conflict: file changed before publication".to_string()
        })?;
        if current[..] != self.original[..] {
            return Err(
                "FIDO2 unlock file update conflict: file changed before publication".into(),
            );
        }
        publish(&self.path, &data, false)
    }
}

/// Security-relevant fields returned by credential creation.
pub struct CreateReply {
    /// Credential identifier allocated by the authenticator.
    pub credential_id: Vec<u8>,
    /// P-256 credential public key encoded as X followed by Y.
    pub public_key: [u8; 64],
    /// Authenticator-data flags observed during credential creation.
    pub flags: u8,
    /// Credential-protection policy reported by the authenticator.
    pub credential_protection: u8,
}

/// Signed assertion fields and the secret extension output.
pub struct AssertReply {
    /// Credential selected by the authenticator from the allow list.
    pub selected_credential_id: Vec<u8>,
    /// WebAuthn authenticator data covered by the signature.
    pub authenticator_data: Vec<u8>,
    /// DER-encoded ES256 assertion signature.
    pub signature: Vec<u8>,
    /// Secret extension output used to derive the wrapper encryption key.
    pub hmac_secret: Zeroizing<[u8; 32]>,
}

/// Backend used for device probing, credential creation, and assertion operations.
pub trait Broker {
    /// Checks that the device backend is available before collecting secrets.
    fn probe(&mut self) -> Result<()>;
    /// Creates a user-verified credential for the relying party.
    fn create(
        &mut self,
        client_data_hash: [u8; 32],
        pin: &[u8],
        label: &str,
    ) -> Result<CreateReply>;
    /// Requests a user-verified assertion and hmac-secret output.
    fn assert(
        &mut self,
        client_data_hash: [u8; 32],
        salt: [u8; 32],
        credential_ids: &[Vec<u8>],
        pin: &[u8],
    ) -> Result<AssertReply>;
}

/// One-shot broker process backend packaged with the enrollment CLI.
pub struct ProcessBroker;

/// Owns a broker process until it has been waited on, including error paths.
struct BrokerChild(Option<Child>);

impl BrokerChild {
    fn child(&mut self) -> &mut Child {
        self.0.as_mut().expect("broker child is available")
    }

    fn wait(mut self) -> std::io::Result<ExitStatus> {
        let result = self.child().wait();
        if result.is_ok() {
            drop(self.0.take());
        }
        result
    }
}

impl Drop for BrokerChild {
    fn drop(&mut self) {
        let Some(child) = self.0.as_mut() else {
            return;
        };
        // Close both protocol pipes before termination, then always wait so an
        // early read, write, parse, or size-limit error cannot leave a zombie.
        drop(child.stdin.take());
        drop(child.stdout.take());
        if child.try_wait().ok().flatten().is_none() {
            let _ = child.kill();
        }
        let _ = child.wait();
    }
}

impl ProcessBroker {
    /// Exchanges one bounded, zeroizing request frame with a fresh broker process.
    fn exchange(&self, operation: u16, payload: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>> {
        let touch_instruction = match operation {
            BROKER_CREATE_OPERATION => Some(CREATE_TOUCH_INSTRUCTION),
            BROKER_ASSERT_OPERATION => Some(ASSERT_TOUCH_INSTRUCTION),
            BROKER_PROBE_OPERATION => None,
            _ => return Err("unsupported broker operation".into()),
        };

        let path = BROKER_PATH.ok_or("enrollment CLI was not built with a packaged broker path")?;
        if !Path::new(path).is_absolute() {
            return Err("packaged broker path is not absolute".into());
        }
        if !path.starts_with("/nix/store/") {
            return Err("packaged broker path is not a Nix store path".into());
        }
        if payload.len() > MAX_BROKER_PAYLOAD {
            return Err("broker request exceeds the maximum payload size".into());
        }

        let mut frame = Zeroizing::new(Vec::with_capacity(
            BROKER_REQUEST_HEADER_LEN + payload.len(),
        ));
        frame.extend_from_slice(BROKER_REQUEST_MAGIC);
        put_u16(&mut frame, BROKER_PROTOCOL_VERSION);
        put_u16(&mut frame, operation);
        put_u32(&mut frame, payload.len() as u32);
        frame.extend_from_slice(&payload[..]);

        // A fresh broker process confines device access and PIN-bearing buffers
        // to a single request.
        if let Some(touch_instruction) = touch_instruction {
            eprintln!("{touch_instruction}");
        }
        let mut child = BrokerChild(Some(
            Command::new(path)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|e| format!("could not start packaged broker: {e}"))?,
        ));

        let mut stdin = child
            .child()
            .stdin
            .take()
            .ok_or("broker stdin unavailable")?;
        stdin
            .write_all(&frame)
            .map_err(|e| format!("could not write broker request: {e}"))?;
        drop(stdin);

        let output = read_limited(
            child
                .child()
                .stdout
                .take()
                .ok_or("broker stdout unavailable")?,
            MAX_BROKER_RESPONSE,
            "broker response",
        )?;
        let status = child
            .wait()
            .map_err(|e| format!("could not wait for broker: {e}"))?;

        // Preserve structured broker diagnostics on failed exits, but never
        // accept a success frame from a process that exited unsuccessfully.
        let parsed = parse_response(operation, &output);
        if status.success() {
            return parsed;
        }

        match parsed {
            Ok(_) => Err("broker exited unsuccessfully after a success response".into()),
            Err(error) => Err(error),
        }
    }
}

impl Broker for ProcessBroker {
    fn probe(&mut self) -> Result<()> {
        let response = self.exchange(BROKER_PROBE_OPERATION, Zeroizing::new(Vec::new()))?;
        parse_probe_reply(&response)
    }

    fn create(
        &mut self,
        client_data_hash: [u8; 32],
        pin: &[u8],
        label: &str,
    ) -> Result<CreateReply> {
        validate_pin(pin)?;
        let mut user_id = [0u8; 16];
        rand_bytes(&mut user_id).map_err(|e| format!("random generation failed: {e}"))?;
        let mut body = Zeroizing::new(Vec::new());
        body.extend_from_slice(&client_data_hash);
        put_bytes(&mut body, RP_ID)?;
        put_bytes(&mut body, b"KeePassXC FIDO2")?;
        put_bytes(&mut body, &user_id)?;
        put_bytes(&mut body, label.as_bytes())?;
        put_bytes(&mut body, label.as_bytes())?;
        put_bytes(&mut body, pin)?;
        user_id.zeroize();

        let response = self.exchange(BROKER_CREATE_OPERATION, body)?;
        parse_create_reply(&response)
    }

    fn assert(
        &mut self,
        client_data_hash: [u8; 32],
        salt: [u8; 32],
        credential_ids: &[Vec<u8>],
        pin: &[u8],
    ) -> Result<AssertReply> {
        validate_pin(pin)?;
        if credential_ids.is_empty() || credential_ids.len() > MAX_WRAPPERS {
            return Err("assertion requires 1 through 8 credential IDs".into());
        }

        let mut seen = HashSet::new();
        let mut body = Zeroizing::new(Vec::new());
        body.extend_from_slice(&client_data_hash);
        body.extend_from_slice(&salt);
        put_bytes(&mut body, RP_ID)?;
        body.push(credential_ids.len() as u8);
        for id in credential_ids {
            if !seen.insert(id.as_slice()) {
                return Err("assertion credential IDs must be distinct".into());
            }
            put_bytes(&mut body, id)?;
        }
        put_bytes(&mut body, pin)?;

        let response = self.exchange(BROKER_ASSERT_OPERATION, body)?;
        parse_assert_reply(&response)
    }
}

/// Derives KeePassXC's PasswordKey as SHA-256 and clears the source buffer.
pub fn password_key(password: &mut Zeroizing<Vec<u8>>) -> Result<Zeroizing<[u8; 32]>> {
    let key = Zeroizing::new(sha256(&password[..]));
    password.zeroize();
    Ok(key)
}

/// Derives KeePassXC's FileKey using XML, binary, hex, then hash precedence.
pub fn load_key_file(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let mut file = File::open(path).map_err(|e| format!("could not open key file: {e}"))?;
    let length = file
        .metadata()
        .map_err(|e| format!("could not stat key file: {e}"))?
        .len();
    load_key_file_from_open(&mut file, length)
}

/// Applies KeePassXC key-file precedence to an already opened file.
fn load_key_file_from_open(file: &mut File, length: u64) -> Result<Zeroizing<[u8; 32]>> {
    if length == 0 {
        return Err("key file is empty".into());
    }

    // Recognized XML has first precedence. Structurally incompatible XML falls
    // through, while semantic errors in a recognized key file remain errors.
    if let Some(key) = load_xml_key_file(file)? {
        return Ok(key);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|e| format!("could not rewind key file: {e}"))?;

    // Exact-size raw and hexadecimal forms precede the generic hash fallback.
    // The EOF recheck prevents stale metadata from truncating a file that grew.
    if length == 32 {
        let mut key = Zeroizing::new([0u8; 32]);
        file.read_exact(&mut key[..])
            .map_err(|e| format!("could not read binary key file: {e}"))?;
        if file_is_at_end(file)? {
            return Ok(key);
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|e| format!("could not rewind key file: {e}"))?;
    }

    if length == 64 {
        let mut encoded = Zeroizing::new([0u8; 64]);
        file.read_exact(&mut encoded[..])
            .map_err(|e| format!("could not read hexadecimal key file: {e}"))?;
        if file_is_at_end(file)?
            && let Ok(key) = decode_hex_key(&encoded[..])
        {
            return Ok(key);
        }
        file.seek(SeekFrom::Start(0))
            .map_err(|e| format!("could not rewind key file: {e}"))?;
    }

    // Every non-empty file not accepted above becomes SHA-256(file bytes).
    let mut hasher = Hasher::new(MessageDigest::sha256())
        .map_err(|e| format!("key file hash setup failed: {e}"))?;
    let mut buffer = Zeroizing::new([0u8; 8192]);
    loop {
        let count = file
            .read(&mut buffer[..])
            .map_err(|e| format!("could not read key file: {e}"))?;
        if count == 0 {
            break;
        }
        hasher
            .update(&buffer[..count])
            .map_err(|e| format!("key file hash failed: {e}"))?;
    }
    let digest = Zeroizing::new(
        hasher
            .finish()
            .map_err(|e| format!("key file hash failed: {e}"))?
            .to_vec(),
    );
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&digest);
    Ok(key)
}

/// Checks the byte after an exact-size candidate without trusting prior metadata.
fn file_is_at_end(file: &mut File) -> Result<bool> {
    let mut extra = Zeroizing::new([0u8; 1]);
    file.read(&mut extra[..])
        .map(|count| count == 0)
        .map_err(|e| format!("could not recheck key file length: {e}"))
}

/// KeePassXC XML key-file encoding version.
#[derive(Clone, Copy)]
enum XmlKeyVersion {
    Version1,
    Version2,
}

/// Parses compatible XML, returning `None` when later key-file fallbacks should run.
fn load_xml_key_file(file: &mut File) -> Result<Option<Zeroizing<[u8; 32]>>> {
    file.seek(SeekFrom::Start(0))
        .map_err(|e| format!("could not rewind key file: {e}"))?;
    // KeePassXC accepts BOM- or declaration-selected XML encodings; normalize
    // them to UTF-8 before applying the same structural key-file checks.
    let mut reader = Reader::from_reader(DecodingReader::new(BufReader::new(file)));
    reader.config_mut().check_comments = true;
    reader.config_mut().check_end_names = true;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Capture {
        None,
        Version,
        Data,
    }

    let mut buffer = Zeroizing::new(Vec::new());
    let mut depth = 0usize;
    let mut root_seen = false;
    let mut root_closed = false;
    let mut meta_depth = None;
    let mut key_depth = None;
    let mut skip_depth = None;
    let mut capture = Capture::None;
    let mut version = Zeroizing::new(String::new());
    let mut data = Zeroizing::new(String::new());
    let mut checksum = Zeroizing::new(String::new());
    let mut current_version = None;
    let mut last_key = None;
    loop {
        buffer.clear();
        let event = match reader.read_event_into(&mut buffer) {
            Ok(event) => event,
            Err(_) => return Ok(None),
        };
        if let Some(skipped_root_depth) = skip_depth {
            match event {
                Event::Start(_) => {
                    depth = match depth.checked_add(1) {
                        Some(depth) => depth,
                        None => return Ok(None),
                    };
                }
                Event::End(_) => {
                    if depth == 0 {
                        return Ok(None);
                    }
                    if depth == skipped_root_depth {
                        skip_depth = None;
                    }
                    depth -= 1;
                }
                Event::Eof => return Ok(None),
                _ => {}
            }
            continue;
        }
        match event {
            Event::Start(element) => {
                if root_closed || capture != Capture::None {
                    return Ok(None);
                }
                let name = element.local_name();
                if depth == 0 {
                    if root_seen || name.as_ref() != "KeyFile" {
                        return Ok(None);
                    }
                    root_seen = true;
                } else if depth == 1 && name.as_ref() == "Meta" {
                    meta_depth = Some(depth + 1);
                } else if depth == 1 && name.as_ref() == "Key" {
                    key_depth = Some(depth + 1);
                } else if depth == 2 && meta_depth == Some(depth) && name.as_ref() == "Version" {
                    version.clear();
                    capture = Capture::Version;
                } else if depth == 2 && key_depth == Some(depth) && name.as_ref() == "Data" {
                    data.clear();
                    if !read_xml_checksum(&element, &mut checksum) {
                        return Ok(None);
                    }
                    capture = Capture::Data;
                } else if name.as_ref() == "Version" || name.as_ref() == "Data" {
                    return Ok(None);
                } else {
                    skip_depth = Some(depth + 1);
                }
                depth = match depth.checked_add(1) {
                    Some(depth) => depth,
                    None => return Ok(None),
                };
            }
            Event::Empty(element) => {
                if root_closed || capture != Capture::None {
                    return Ok(None);
                }
                let name = element.local_name();
                if depth == 0 {
                    if root_seen || name.as_ref() != "KeyFile" {
                        return Ok(None);
                    }
                    root_seen = true;
                    root_closed = true;
                } else if depth == 2 && meta_depth == Some(depth) && name.as_ref() == "Version" {
                    version.clear();
                    current_version = Some(parse_xml_key_version(&version)?);
                } else if depth == 2 && key_depth == Some(depth) && name.as_ref() == "Data" {
                    data.clear();
                    if !read_xml_checksum(&element, &mut checksum) {
                        return Ok(None);
                    }
                    last_key = finish_xml_data(current_version, &data, &checksum)?;
                } else if name.as_ref() == "Version" || name.as_ref() == "Data" {
                    return Ok(None);
                }
            }
            Event::Text(text) => {
                let target = match capture {
                    Capture::Version => &mut version,
                    Capture::Data => &mut data,
                    Capture::None => {
                        if depth == 0 && !text.xml10_content().trim().is_empty() {
                            return Ok(None);
                        }
                        continue;
                    }
                };
                target.push_str(&text.xml10_content());
            }
            Event::CData(text) => {
                let target = match capture {
                    Capture::Version => &mut version,
                    Capture::Data => &mut data,
                    Capture::None => {
                        if depth == 0 && !text.xml10_content().trim().is_empty() {
                            return Ok(None);
                        }
                        continue;
                    }
                };
                target.push_str(&text.xml10_content());
            }
            Event::GeneralRef(reference) if capture != Capture::None => {
                let target = match capture {
                    Capture::Version => &mut version,
                    Capture::Data => &mut data,
                    Capture::None => unreachable!(),
                };
                let character = match reference.resolve_char_ref() {
                    Ok(character) => character,
                    Err(_) => return Ok(None),
                };
                if let Some(character) = character {
                    target.push(character);
                } else {
                    target.push_str(match reference.as_ref() {
                        "amp" => "&",
                        "lt" => "<",
                        "gt" => ">",
                        "apos" => "'",
                        "quot" => "\"",
                        _ => return Ok(None),
                    });
                }
            }
            Event::GeneralRef(_) if depth == 0 => return Ok(None),
            Event::End(element) => {
                if depth == 0 {
                    return Ok(None);
                }
                let name = element.local_name();
                if capture == Capture::Version {
                    if depth != 3 || name.as_ref() != "Version" {
                        return Ok(None);
                    }
                    capture = Capture::None;
                    current_version = Some(parse_xml_key_version(&version)?);
                } else if capture == Capture::Data {
                    if depth != 3 || name.as_ref() != "Data" {
                        return Ok(None);
                    }
                    capture = Capture::None;
                    last_key = finish_xml_data(current_version, &data, &checksum)?;
                }
                if depth == 2 && meta_depth == Some(depth) && name.as_ref() == "Meta" {
                    meta_depth = None;
                } else if depth == 2 && key_depth == Some(depth) && name.as_ref() == "Key" {
                    key_depth = None;
                } else if depth == 1 {
                    if name.as_ref() != "KeyFile" {
                        return Ok(None);
                    }
                    root_closed = true;
                }
                depth -= 1;
            }
            Event::Decl(_) | Event::DocType(_) if root_seen => return Ok(None),
            Event::Eof => {
                if depth != 0 || !root_closed || capture != Capture::None {
                    return Ok(None);
                }
                break;
            }
            _ => {}
        }
    }
    Ok(last_key)
}

fn parse_xml_key_version(version: &str) -> Result<XmlKeyVersion> {
    if version.starts_with("1.0") {
        Ok(XmlKeyVersion::Version1)
    } else if version == "2.0" {
        Ok(XmlKeyVersion::Version2)
    } else {
        Err(format!(
            "unsupported XML key file version: {}",
            display_label(version)
        ))
    }
}

/// Decodes and verifies one XML Data element under the active format version.
fn finish_xml_data(
    version: Option<XmlKeyVersion>,
    data: &str,
    checksum: &str,
) -> Result<Option<Zeroizing<[u8; 32]>>> {
    let version = version.ok_or_else(|| "unexpected XML key file data".to_string())?;
    let compact: Zeroizing<String> = Zeroizing::new(
        data.chars()
            .filter(|character| !character.is_whitespace())
            .collect(),
    );
    let decoded = match version {
        XmlKeyVersion::Version1 if compact.is_empty() => Zeroizing::new(Vec::new()),
        XmlKeyVersion::Version1 => decode_base64_key(&compact)?,
        XmlKeyVersion::Version2 => {
            let decoded = if compact.is_empty() {
                Zeroizing::new(Vec::new())
            } else {
                decode_hex_data(compact.as_bytes())?
            };
            let expected = decode_hex_data(checksum.as_bytes())?;
            let actual = Zeroizing::new(sha256(&decoded));
            if expected.len() != 4 || actual[..4] != expected[..] {
                return Err("XML key file checksum mismatch".into());
            }
            decoded
        }
    };
    if decoded.is_empty() {
        Ok(None)
    } else {
        Ok(Some(raw_file_key(&decoded)))
    }
}

fn read_xml_checksum(
    element: &quick_xml::events::BytesStart<'_>,
    checksum: &mut Zeroizing<String>,
) -> bool {
    checksum.clear();
    for attribute in element.attributes() {
        let attribute = match attribute {
            Ok(attribute) => attribute,
            Err(_) => return false,
        };
        if attribute.key.local_name().as_ref() == "Hash" {
            let value = match attribute.normalized_value(XmlVersion::Implicit1_0) {
                Ok(value) => value,
                Err(_) => return false,
            };
            checksum.push_str(&value);
        }
    }
    true
}

fn decode_base64_key(value: &str) -> Result<Zeroizing<Vec<u8>>> {
    let padding = value.bytes().rev().take_while(|byte| *byte == b'=').count();
    let content_length = value.len().saturating_sub(padding);
    if value.is_empty()
        || !value.len().is_multiple_of(4)
        || padding > 2
        || !value.as_bytes()[..content_length]
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'+' || *byte == b'/')
        || !value.as_bytes()[content_length..]
            .iter()
            .all(|byte| *byte == b'=')
        || (padding == 1 && content_length % 4 != 3)
        || (padding == 2 && content_length % 4 != 2)
    {
        return Err("invalid base64 XML key file data".into());
    }
    Ok(Zeroizing::new(
        base64::decode_block(value).map_err(|_| "invalid base64 XML key file data")?,
    ))
}

fn decode_hex_key(value: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let decoded = decode_hex_data(value)?;
    if decoded.len() != 32 {
        return Err("hexadecimal key file must encode exactly 32 bytes".into());
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&decoded);
    Ok(key)
}

fn decode_hex_data(value: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || !value.iter().all(u8::is_ascii_hexdigit)
    {
        return Err("invalid hexadecimal key file data".into());
    }
    let mut decoded = Zeroizing::new(Vec::with_capacity(value.len() / 2));
    for pair in value.chunks_exact(2) {
        let text = std::str::from_utf8(pair).map_err(|_| "invalid hexadecimal key file data")?;
        decoded
            .push(u8::from_str_radix(text, 16).map_err(|_| "invalid hexadecimal key file data")?);
    }
    Ok(decoded)
}

/// Normalizes decoded XML data by zero-padding or truncating to 32 bytes.
fn raw_file_key(data: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    let length = data.len().min(key.len());
    key[..length].copy_from_slice(&data[..length]);
    key
}

/// Creates and verifies a FIDO2 wrapper before adding it to a canonical FIDO2 unlock file.
pub fn enroll_new(
    existing: Option<Fido2UnlockFile>,
    payload_policy: PayloadPolicy,
    label: String,
    password_key: &Zeroizing<[u8; 32]>,
    file_key: &Zeroizing<[u8; 32]>,
    pin: &mut Zeroizing<Vec<u8>>,
    broker: &mut dyn Broker,
) -> Result<Fido2UnlockFile> {
    validate_label(&label)?;

    let mut unlock_file = match existing {
        Some(value) => {
            if value.payload_policy != payload_policy {
                return Err("append payload policy does not match the FIDO2 unlock file".into());
            }
            value
        }
        None => Fido2UnlockFile {
            envelope_id: random_array()?,
            envelope_salt: random_array()?,
            payload_policy,
            wrappers: Vec::new(),
        },
    };
    if unlock_file.wrappers.len() >= MAX_WRAPPERS {
        return Err("FIDO2 unlock file already has the maximum of eight wrappers".into());
    }

    let mut slot_id: [u8; 16];
    loop {
        slot_id = random_array()?;
        if !unlock_file.wrappers.iter().any(|w| w.slot_id == slot_id) {
            break;
        }
    }

    let client_data_hash = random_array()?;
    let created = broker.create(client_data_hash, pin, &label)?;
    if created.flags & REQUIRED_AUTH_DATA_FLAGS != REQUIRED_AUTH_DATA_FLAGS
        || created.credential_protection != CREDENTIAL_PROTECTION_UV_REQUIRED
    {
        return Err(
            "broker returned a credential without required UP, UV, or credProtect policy".into(),
        );
    }
    validate_credential_id(&created.credential_id)?;
    if unlock_file
        .wrappers
        .iter()
        .any(|wrapper| wrapper.credential_id == created.credential_id)
    {
        return Err("broker created a duplicate credential ID".into());
    }

    // Verify credential selection, RP binding, UP/UV flags, and signature before
    // deriving or retaining any wrapper from the returned hmac-secret output.
    let assertion_hash = random_array()?;
    let assertion = broker.assert(
        assertion_hash,
        unlock_file.envelope_salt,
        std::slice::from_ref(&created.credential_id),
        pin,
    )?;
    if assertion.selected_credential_id != created.credential_id {
        return Err(
            "broker assertion selected a credential other than the newly created one".into(),
        );
    }
    verify_assertion(&created.public_key, &assertion, assertion_hash)?;

    let ciphertext = encrypt_wrapper(
        &unlock_file,
        &slot_id,
        &created,
        password_key,
        file_key,
        &assertion.hmac_secret,
    )?;
    let wrapper = Wrapper {
        slot_id,
        label,
        credential_id: created.credential_id,
        public_key: created.public_key,
        nonce: ciphertext.0,
        ciphertext: ciphertext.1,
    };

    unlock_file.wrappers.push(wrapper);

    // Canonical FIDO2 unlock files are strictly ordered by raw slot ID.
    unlock_file.wrappers.sort_by_key(|wrapper| wrapper.slot_id);
    Ok(unlock_file)
}

/// Parses a FIDO2 unlock file and rejects non-canonical ordering, duplicates, and policy bytes.
pub fn parse_unlock_file(data: &[u8]) -> Result<Fido2UnlockFile> {
    if data.len() > MAX_FILE || data.len() < HEADER_LEN {
        return Err("FIDO2 unlock file length is invalid".into());
    }

    let mut cursor = Cursor::new(data);
    if cursor.take(8)? != UNLOCK_FILE_MAGIC {
        return Err("FIDO2 unlock file magic is invalid".into());
    }
    if cursor.u16()? != UNLOCK_FILE_VERSION || cursor.u32()? as usize != data.len() {
        return Err("FIDO2 unlock file version or total length is invalid".into());
    }

    let envelope_id = cursor.array()?;
    if cursor.take(28)? != RP_ID {
        return Err("FIDO2 unlock file RP ID is invalid".into());
    }
    let envelope_salt = cursor.array()?;
    let payload_policy = PayloadPolicy::try_from(cursor.u8()?)?;
    let count = cursor.u8()? as usize;
    if !(1..=MAX_WRAPPERS).contains(&count) || cursor.take(2)? != [0, 0] {
        return Err("FIDO2 unlock file wrapper count or reserved bytes are invalid".into());
    }

    let mut wrappers = Vec::with_capacity(count);
    let mut previous: Option<[u8; 16]> = None;
    let mut credential_ids = HashSet::new();
    for _ in 0..count {
        let slot_id = cursor.array()?;
        if previous.is_some_and(|prior| prior >= slot_id) {
            return Err("FIDO2 unlock file wrapper slot IDs are not strictly ordered".into());
        }
        previous = Some(slot_id);

        let label_length = cursor.u8()? as usize;
        if !(1..=128).contains(&label_length) {
            return Err("FIDO2 unlock file label length is invalid".into());
        }
        let label_bytes = cursor.take(label_length)?;
        let label = std::str::from_utf8(label_bytes)
            .map_err(|_| "FIDO2 unlock file label is not UTF-8")?
            .to_owned();
        validate_label(&label)?;

        let credential_length = cursor.u16()? as usize;
        if !(1..=1024).contains(&credential_length) {
            return Err("FIDO2 unlock file credential ID length is invalid".into());
        }
        let credential_id = cursor.take(credential_length)?.to_vec();
        if !credential_ids.insert(credential_id.clone()) {
            return Err("FIDO2 unlock file has duplicate credential IDs".into());
        }

        let public_key = cursor.array()?;
        p256_public_key(&public_key)?;
        let nonce = cursor.array()?;
        let ciphertext = cursor.array()?;
        if cursor.u8()? != WRAPPER_UV_POLICY_REQUIRED || cursor.take(3)? != [0, 0, 0] {
            return Err("FIDO2 unlock file UV policy or reserved bytes are invalid".into());
        }

        wrappers.push(Wrapper {
            slot_id,
            label,
            credential_id,
            public_key,
            nonce,
            ciphertext,
        });
    }

    if !cursor.at_end() {
        return Err("FIDO2 unlock file has trailing bytes".into());
    }
    Ok(Fido2UnlockFile {
        envelope_id,
        envelope_salt,
        payload_policy,
        wrappers,
    })
}

/// Serializes an unlock file after enforcing canonical order and field invariants.
pub fn serialize_unlock_file(unlock_file: &Fido2UnlockFile) -> Result<Vec<u8>> {
    if !(1..=MAX_WRAPPERS).contains(&unlock_file.wrappers.len()) {
        return Err("FIDO2 unlock file must contain 1 through 8 wrappers".into());
    }

    // Emit the fixed header in wire order; all multi-byte integers are big-endian.
    let mut body = Vec::new();
    body.extend_from_slice(UNLOCK_FILE_MAGIC);
    put_u16(&mut body, UNLOCK_FILE_VERSION);
    put_u32(&mut body, 0);
    body.extend_from_slice(&unlock_file.envelope_id);
    body.extend_from_slice(RP_ID);
    body.extend_from_slice(&unlock_file.envelope_salt);
    body.push(unlock_file.payload_policy as u8);
    body.push(unlock_file.wrappers.len() as u8);
    body.extend_from_slice(&[0; 2]);

    // Reject non-canonical input rather than silently reordering caller data.
    let mut previous: Option<[u8; 16]> = None;
    let mut credentials = HashSet::new();
    for wrapper in &unlock_file.wrappers {
        if previous.is_some_and(|prior| prior >= wrapper.slot_id) {
            return Err("wrappers must be sorted by slot ID".into());
        }
        previous = Some(wrapper.slot_id);
        validate_label(&wrapper.label)?;
        validate_credential_id(&wrapper.credential_id)?;
        if !credentials.insert(wrapper.credential_id.as_slice()) {
            return Err("wrappers must have distinct credential IDs".into());
        }

        body.extend_from_slice(&wrapper.slot_id);
        body.push(wrapper.label.len() as u8);
        body.extend_from_slice(wrapper.label.as_bytes());
        put_bytes(&mut body, &wrapper.credential_id)?;
        body.extend_from_slice(&wrapper.public_key);
        body.extend_from_slice(&wrapper.nonce);
        body.extend_from_slice(&wrapper.ciphertext);
        body.push(WRAPPER_UV_POLICY_REQUIRED);
        body.extend_from_slice(&[0; 3]);
    }

    if body.len() > MAX_FILE {
        return Err("FIDO2 unlock file exceeds the maximum file size".into());
    }

    // Header bytes 10..14 hold total-file-length after every wrapper is encoded.
    let total_length = body.len() as u32;
    body[10..14].copy_from_slice(&total_length.to_be_bytes());
    Ok(body)
}

/// Reads and validates a bounded FIDO2 unlock file from a regular file.
pub fn read_unlock_file(path: &Path) -> Result<Fido2UnlockFile> {
    let (file, _) = open_unlock_file(path)?;
    let data = read_limited(file, MAX_FILE, "FIDO2 unlock file")?;
    parse_unlock_file(&data)
}

/// Opens a bounded regular unlock file without following symlinks or blocking on FIFOs.
fn open_unlock_file(path: &Path) -> Result<(File, fs::Metadata)> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| format!("could not open FIDO2 unlock file: {e}"))?;
    let metadata = file
        .metadata()
        .map_err(|e| format!("could not stat opened FIDO2 unlock file: {e}"))?;
    if !metadata.is_file() || metadata.len() > MAX_FILE as u64 {
        return Err("FIDO2 unlock file is not a regular file within the size limit".into());
    }
    Ok((file, metadata))
}

/// Publishes a new FIDO2 unlock file without replacing an existing path.
pub fn create_unlock_file(path: &Path, unlock_file: &Fido2UnlockFile) -> Result<()> {
    publish(path, &serialize_unlock_file(unlock_file)?, true)
}

/// Atomically replaces a FIDO2 unlock file with canonical serialized data.
pub fn replace_unlock_file(path: &Path, unlock_file: &Fido2UnlockFile) -> Result<()> {
    publish(path, &serialize_unlock_file(unlock_file)?, false)
}

/// Removes a wrapper while refusing to leave an unusable empty FIDO2 unlock file.
pub fn remove_wrapper(unlock_file: &mut Fido2UnlockFile, slot_id: [u8; 16]) -> Result<()> {
    if unlock_file.wrappers.len() == 1 {
        return Err(
            "refusing to remove the final wrapper; delete the FIDO2 unlock file explicitly instead"
                .into(),
        );
    }
    let position = unlock_file
        .wrappers
        .iter()
        .position(|wrapper| wrapper.slot_id == slot_id)
        .ok_or("slot ID was not found")?;
    unlock_file.wrappers.remove(position);
    Ok(())
}

/// Publishes prepared bytes through a private same-directory temporary file.
fn publish(path: &Path, data: &[u8], no_clobber: bool) -> Result<()> {
    let parent = parent_directory(path);
    let mut random = [0u8; 16];
    rand_bytes(&mut random).map_err(|e| format!("random generation failed: {e}"))?;
    let temp = parent.join(format!(".{}.tmp", hex(&random)));

    // Prepare complete mode-0600 contents and fsync them before the publication
    // operation can make any destination path visible.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|e| format!("could not create temporary FIDO2 unlock file: {e}"))?;

    let preparation = (|| {
        file.write_all(data)
            .map_err(|e| format!("could not write temporary FIDO2 unlock file: {e}"))?;
        file.sync_all()
            .map_err(|e| format!("could not fsync temporary FIDO2 unlock file: {e}"))?;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("could not set FIDO2 unlock file permissions: {e}"))?;
        Ok(())
    })();
    drop(file);
    if let Err(error) = preparation {
        let _ = fs::remove_file(&temp);
        return Err(error);
    }

    // The publication step is atomic: hard_link provides no-clobber creation,
    // while rename provides replacement at the destination path.
    let committed = if no_clobber {
        fs::hard_link(&temp, path)
            .map_err(|e| format!("could not create FIDO2 unlock file without clobbering: {e}"))
    } else {
        fs::rename(&temp, path)
            .map_err(|e| format!("could not atomically replace FIDO2 unlock file: {e}"))
    };
    if let Err(error) = committed {
        let _ = fs::remove_file(&temp);
        return Err(error);
    }

    // Once link or rename succeeds, the destination is already published.
    // Temporary-link cleanup and directory fsync failures therefore only warn.
    if no_clobber {
        warn_after_publish(
            fs::remove_file(&temp),
            "could not remove the temporary FIDO2 unlock file link",
        );
    }
    warn_after_publish(
        File::open(parent).and_then(|directory| directory.sync_all()),
        "could not fsync the FIDO2 unlock file directory",
    );
    Ok(())
}

fn warn_after_publish(result: std::io::Result<()>, message: &str) {
    if let Err(error) = result {
        let stderr = std::io::stderr();
        write_post_publish_warning(&mut stderr.lock(), message, &error);
    }
}

fn write_post_publish_warning(writer: &mut impl Write, message: &str, error: &std::io::Error) {
    let _ = writeln!(
        writer,
        "warning: FIDO2 unlock file was published but {message}: {error}"
    );
}

/// Encrypts PasswordKey || FileKey under an hmac-secret-derived wrapper key.
fn encrypt_wrapper(
    unlock_file: &Fido2UnlockFile,
    slot_id: &[u8; 16],
    created: &CreateReply,
    password_key: &Zeroizing<[u8; 32]>,
    file_key: &Zeroizing<[u8; 32]>,
    hmac_secret: &Zeroizing<[u8; 32]>,
) -> Result<([u8; 12], [u8; 80])> {
    let nonce = random_array()?;
    let aad = aad(
        unlock_file.payload_policy,
        &unlock_file.envelope_id,
        slot_id,
        &created.credential_id,
        &created.public_key,
        &unlock_file.envelope_salt,
    );
    let kek = hkdf(hmac_secret, &unlock_file.envelope_id, slot_id)?;
    let mut crypter = Crypter::new(Cipher::aes_256_gcm(), Mode::Encrypt, &kek[..], Some(&nonce))
        .map_err(|e| format!("AES-GCM setup failed: {e}"))?;
    crypter
        .aad_update(&aad)
        .map_err(|e| format!("AES-GCM AAD failed: {e}"))?;
    // Payload layout is fixed: PasswordKey first, then FileKey. Password-only
    // wrappers require the FileKey half to remain the canonical all-zero value.
    let mut plaintext = Zeroizing::new([0u8; 64]);
    plaintext[..32].copy_from_slice(&password_key[..]);
    plaintext[32..].copy_from_slice(&file_key[..]);
    if unlock_file.payload_policy == PayloadPolicy::PasswordOnly && plaintext[32..] != [0; 32] {
        return Err("password-only payload requires a zero FileKey".into());
    }

    let mut output = [0u8; 80];
    let count = crypter
        .update(&plaintext[..], &mut output)
        .map_err(|e| format!("AES-GCM encryption failed: {e}"))?;
    let finalized = crypter
        .finalize(&mut output[count..])
        .map_err(|e| format!("AES-GCM finalization failed: {e}"))?;
    if count != 64 || finalized != 0 {
        return Err("AES-GCM did not produce exactly 64 ciphertext bytes".into());
    }
    let mut tag = Zeroizing::new([0u8; 16]);
    crypter
        .get_tag(&mut tag[..])
        .map_err(|e| format!("AES-GCM tag failed: {e}"))?;
    output[64..].copy_from_slice(&tag[..]);
    Ok((nonce, output))
}

/// Verifies RP binding, UP/UV flags, and the ES256 assertion signature.
fn verify_assertion(
    public_key: &[u8; 64],
    reply: &AssertReply,
    client_data_hash: [u8; 32],
) -> Result<()> {
    if reply.authenticator_data.len() < 37 {
        return Err("assertion authenticator data is too short".into());
    }

    // Bind the assertion to this protocol's relying party before trusting its
    // flags, signature, or hmac-secret output.
    let rp_hash =
        hash(MessageDigest::sha256(), RP_ID).map_err(|e| format!("RP hash failed: {e}"))?;
    if reply.authenticator_data[..32] != rp_hash[..] {
        return Err("assertion RP ID hash is invalid".into());
    }
    let flags = reply.authenticator_data[32];
    if flags & REQUIRED_AUTH_DATA_FLAGS != REQUIRED_AUTH_DATA_FLAGS {
        return Err("assertion did not require both user presence and verification".into());
    }

    let pkey = p256_public_key(public_key)?;

    // WebAuthn signs authenticatorData followed by clientDataHash.
    let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey)
        .map_err(|e| format!("signature verifier setup failed: {e}"))?;
    verifier
        .update(&reply.authenticator_data)
        .map_err(|e| format!("signature verifier update failed: {e}"))?;
    verifier
        .update(&client_data_hash)
        .map_err(|e| format!("signature verifier update failed: {e}"))?;
    if !verifier
        .verify(&reply.signature)
        .map_err(|e| format!("signature verification failed: {e}"))?
    {
        return Err("assertion ES256 signature is invalid".into());
    }
    Ok(())
}

/// Validates raw affine P-256 coordinates and constructs an OpenSSL public key.
fn p256_public_key(public_key: &[u8; 64]) -> Result<PKey<Public>> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
        .map_err(|e| format!("P-256 unavailable: {e}"))?;
    let x = BigNum::from_slice(&public_key[..32])
        .map_err(|e| format!("invalid public key X coordinate: {e}"))?;
    let y = BigNum::from_slice(&public_key[32..])
        .map_err(|e| format!("invalid public key Y coordinate: {e}"))?;
    let key = EcKey::from_public_key_affine_coordinates(&group, &x, &y)
        .map_err(|e| format!("invalid P-256 public key: {e}"))?;
    key.check_key()
        .map_err(|e| format!("invalid P-256 public key: {e}"))?;
    PKey::from_ec_key(key).map_err(|e| format!("P-256 key construction failed: {e}"))
}

/// Derives a slot-specific AES-256 wrapper key using HKDF-SHA-256.
fn hkdf(
    ikm: &Zeroizing<[u8; 32]>,
    salt: &[u8; 16],
    slot_id: &[u8; 16],
) -> Result<Zeroizing<[u8; 32]>> {
    // RFC 5869 extract uses the envelope ID as salt.
    let prk = hmac(salt, &ikm[..])?;

    // One SHA-256 expand block is sufficient for the 32-byte KEK.
    let mut info = Zeroizing::new(b"keepassxc-fido2-unlock-file-v1-kek".to_vec());
    info.extend_from_slice(slot_id);
    info.push(HKDF_FIRST_BLOCK);
    hmac(&prk[..], &info[..])
}

fn hmac(key: &[u8], input: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let pkey = PKey::hmac(key).map_err(|e| format!("HMAC key setup failed: {e}"))?;
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey)
        .map_err(|e| format!("HMAC setup failed: {e}"))?;
    signer
        .update(input)
        .map_err(|e| format!("HMAC update failed: {e}"))?;
    let digest = Zeroizing::new(
        signer
            .sign_to_vec()
            .map_err(|e| format!("HMAC failed: {e}"))?,
    );
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    Ok(Zeroizing::new(output))
}

/// Constructs the canonical metadata transcript authenticated by AES-GCM.
fn aad(
    payload_policy: PayloadPolicy,
    envelope_id: &[u8; 16],
    slot_id: &[u8; 16],
    credential_id: &[u8],
    public_key: &[u8; 64],
    salt: &[u8; 32],
) -> Vec<u8> {
    // Canonical A2 v1 field order must match KeePassXC associatedData().
    // Length prefixes make variable fields unambiguous in the authenticated transcript.
    let mut value = Vec::new();
    value.extend_from_slice(AAD_MAGIC);
    put_u32(&mut value, AAD_VERSION);
    value.push(payload_policy as u8);

    value.extend_from_slice(envelope_id);
    value.extend_from_slice(slot_id);

    put_u16(&mut value, RP_ID.len() as u16);
    value.extend_from_slice(RP_ID);

    put_u16(&mut value, credential_id.len() as u16);
    value.extend_from_slice(credential_id);

    value.extend_from_slice(public_key);
    value.extend_from_slice(salt);
    value.push(WRAPPER_UV_POLICY_REQUIRED);
    value
}

/// Validates a bounded broker response frame and returns its zeroizing payload.
fn parse_response(operation: u16, response: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if response.len() < BROKER_RESPONSE_HEADER_LEN
        || response.len() > MAX_BROKER_RESPONSE
        || &response[..4] != BROKER_RESPONSE_MAGIC
    {
        return Err("broker response header is invalid".into());
    }
    let mut cursor = Cursor::new(response);
    cursor.take(4)?;
    if cursor.u16()? != BROKER_PROTOCOL_VERSION || cursor.u16()? != operation {
        return Err("broker response version or operation is invalid".into());
    }
    let status = cursor.u16()?;
    if cursor.u16()? != 0 {
        return Err("broker response reserved bytes are invalid".into());
    }
    let length = cursor.u32()? as usize;
    let payload = cursor.take(length)?;
    if !cursor.at_end() {
        return Err("broker response has trailing bytes".into());
    }
    if status != 0 {
        if payload.len() > 256 {
            return Err("broker returned an invalid error response".into());
        }
        let diagnostic = std::str::from_utf8(payload)
            .map_err(|_| "broker returned an invalid error response")?;
        if diagnostic.is_empty() {
            return Err(format!("broker failed with status {status}"));
        }
        return Err(format!(
            "broker failed with status {status}: {}",
            display_label(diagnostic)
        ));
    }
    Ok(Zeroizing::new(payload.to_vec()))
}

fn parse_create_reply(payload: &[u8]) -> Result<CreateReply> {
    let mut cursor = Cursor::new(payload);
    let credential_id = cursor.var_bytes(1, 1024)?;
    let public_key = cursor.array()?;
    let flags = cursor.u8()?;
    let credential_protection = cursor.u8()?;
    if !cursor.at_end() {
        return Err("broker create response has trailing bytes".into());
    }
    Ok(CreateReply {
        credential_id,
        public_key,
        flags,
        credential_protection,
    })
}

fn parse_probe_reply(payload: &[u8]) -> Result<()> {
    if payload.is_empty() {
        Ok(())
    } else {
        Err("broker probe response payload is not empty".into())
    }
}

fn parse_assert_reply(payload: &[u8]) -> Result<AssertReply> {
    let mut cursor = Cursor::new(payload);
    let selected_credential_id = cursor.var_bytes(1, 1024)?;
    let authenticator_data = cursor.var_bytes(1, 2048)?;
    let signature = cursor.var_bytes(1, 256)?;
    let hmac_secret = cursor.sensitive_array()?;
    if !cursor.at_end() {
        return Err("broker assert response has trailing bytes".into());
    }
    Ok(AssertReply {
        selected_credential_id,
        authenticator_data,
        signature,
        hmac_secret,
    })
}

fn validate_label(label: &str) -> Result<()> {
    if label.is_empty() || label.len() > 128 || label.as_bytes().contains(&0) {
        return Err("label must be 1 through 128 UTF-8 bytes without NUL".into());
    }
    Ok(())
}

fn validate_credential_id(id: &[u8]) -> Result<()> {
    if !(1..=1024).contains(&id.len()) {
        return Err("credential ID must be 1 through 1024 bytes".into());
    }
    Ok(())
}

/// Enforces the broker protocol's bounded UTF-8 PIN representation.
fn validate_pin(pin: &[u8]) -> Result<()> {
    if !(4..=63).contains(&pin.len()) || pin.contains(&0) || std::str::from_utf8(pin).is_err() {
        return Err("FIDO PIN must be 4 through 63 UTF-8 bytes without NUL".into());
    }
    Ok(())
}

/// Reads at most `maximum` bytes and rejects an input with any additional byte.
fn read_limited(mut reader: impl Read, maximum: usize, name: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut data = Zeroizing::new(Vec::with_capacity(maximum.min(4096)));
    reader
        .by_ref()
        .take((maximum + 1) as u64)
        .read_to_end(&mut data)
        .map_err(|e| format!("could not read {name}: {e}"))?;
    if data.len() > maximum {
        return Err(format!("{name} exceeds the maximum size"));
    }
    Ok(data)
}

fn parent_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut bytes = [0u8; N];
    rand_bytes(&mut bytes).map_err(|e| format!("random generation failed: {e}"))?;
    Ok(bytes)
}

fn put_u16(target: &mut Vec<u8>, value: u16) {
    target.extend_from_slice(&value.to_be_bytes());
}
fn put_u32(target: &mut Vec<u8>, value: u32) {
    target.extend_from_slice(&value.to_be_bytes());
}
fn put_bytes(target: &mut Vec<u8>, value: &[u8]) -> Result<()> {
    let length: u16 = value
        .len()
        .try_into()
        .map_err(|_| "field exceeds u16 length".to_string())?;
    put_u16(target, length);
    target.extend_from_slice(value);
    Ok(())
}

/// Forward-only cursor with checked ranges and explicit trailing-data checks.
struct Cursor<'a> {
    data: &'a [u8],
    position: usize,
}
impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(count)
            .ok_or("binary length overflow")?;
        let value = self
            .data
            .get(self.position..end)
            .ok_or("unexpected end of binary data")?;
        self.position = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| "u16 read failed")?,
        ))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| "u32 read failed")?,
        ))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?
            .try_into()
            .map_err(|_| "fixed-width read failed".into())
    }

    fn sensitive_array<const N: usize>(&mut self) -> Result<Zeroizing<[u8; N]>> {
        Ok(Zeroizing::new(self.array()?))
    }

    fn var_bytes(&mut self, min: usize, max: usize) -> Result<Vec<u8>> {
        let length = self.u16()? as usize;
        if !(min..=max).contains(&length) {
            return Err("binary field length is invalid".into());
        }
        Ok(self.take(length)?.to_vec())
    }

    fn at_end(&self) -> bool {
        self.position == self.data.len()
    }
}

/// Encodes bytes as canonical lowercase hexadecimal text.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}

/// Parses the canonical lowercase hexadecimal representation of a slot ID.
pub fn parse_hex_slot(value: &str) -> Result<[u8; 16]> {
    if value.len() != 32
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return Err("slot ID must be 32 lowercase hexadecimal characters".into());
    }
    let mut result = [0u8; 16];
    for (index, output) in result.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "slot ID is not hexadecimal")?;
    }
    Ok(result)
}

/// Escapes untrusted label text for safe single-line terminal display.
pub fn display_label(label: &str) -> String {
    label.escape_default().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::{ffi::OsStrExt, fs::symlink};

    const FROZEN_PASSWORD_ONLY_UNLOCK_FILE_HEX: &str = concat!(
        "4b50594b554e4c4b000100000201000102030405060708090a0b0c0d0e0f6669646f322d656e76656c6f70652e6b65657061737378632e",
        "6f7267202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f01020000101112131415161718191a1b1c1d1e1f",
        "0f5072696d61727920597562694b65790010a0a1a2a3a4a5a6a7a8a9aaabacadaeaf6b17d1f2e12c4247f8bce6e563a440f277037d812d",
        "eb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5c0c1c2c3c4c5c6c7c8c9cacb",
        "b8b6dafdb625f7a9cf872ef84021a1ebd1e7d234af5e21c7182d650c30ccfbad78782a9eaa00fa8c622f709c68344cbf8a0c45aadf6806",
        "bc45d0a3156c8d2070d4c57e355761a5f55ab16dae6e1cf07701000000505152535455565758595a5b5c5d5e5f0e4261636b7570205975",
        "62694b65790010b0b1b2b3b4b5b6b7b8b9babbbcbdbebf7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1d0d1d2d3d4d5d6d7d8d9dadb8a8e39431f2950638ee558",
        "95d62d86da0c321f061b7708390ec0a604706407422125cd0bc0cda5f33a6511e29690c1b6f586e6cd2bcef6b5b2df1165831f2ebddcf0",
        "9f4b2928d0ba3beb373a5ea581b601000000",
    );
    const FROZEN_PASSWORD_AND_KEY_FILE_UNLOCK_FILE_HEX: &str = concat!(
        "4b50594b554e4c4b000100000201000102030405060708090a0b0c0d0e0f6669646f322d656e76656c6f70652e6b65657061737378632e",
        "6f7267202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f02020000101112131415161718191a1b1c1d1e1f",
        "0f5072696d61727920597562694b65790010a0a1a2a3a4a5a6a7a8a9aaabacadaeaf6b17d1f2e12c4247f8bce6e563a440f277037d812d",
        "eb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5c0c1c2c3c4c5c6c7c8c9cacb",
        "b8b6dafdb625f7a9cf872ef84021a1ebd1e7d234af5e21c7182d650c30ccfbad7879289dae05fc8b6a267a97643942b09a1d57b9cb7d10",
        "ab5dc9b90e70903e6f75821c833fbb0663a8852f1d8be2f12801000000505152535455565758595a5b5c5d5e5f0e4261636b7570205975",
        "62694b65790010b0b1b2b3b4b5b6b7b8b9babbbcbdbebf7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
        "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1d0d1d2d3d4d5d6d7d8d9dadb8a8e39431f2950638ee558",
        "95d62d86da0c321f061b7708390ec0a604706407422124cf08c4c8a3f4326c1be99a9dcfb9e597f4de3fdbe0a2aac60b7e9f0230a27bf9",
        "bc9cb56ff7ccbcb6fd4d4beb31b801000000",
    );
    const HKDF_SLOT_HEX: &str = "101112131415161718191a1b1c1d1e1f";
    const HKDF_ENVELOPE_HEX: &str = "000102030405060708090a0b0c0d0e0f";
    const HKDF_SECRET_HEX: &str =
        "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f";
    const EXPECTED_KEK_HEX: &str =
        "7cd7d262476ba3900819bec1ac1f1734ead09312a38d15fccbc9aa85e85ea080";
    const EXPECTED_PASSWORD_KEY_HEX: &str =
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
    const EXPECTED_FILE_KEY_HEX: &str =
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const VALID_CREATE_RESPONSE_HEX: &str = concat!(
        "4b5059520001000100000000000000540010b0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0503",
    );
    const ERROR_RESPONSE_HEX: &str = "4b505952000100020006000000000003626164";
    const VALID_PROBE_RESPONSE_HEX: &str = "4b505952000100030000000000000000";
    const TEST_PIN: &[u8] = b"1234";
    const TEST_PASSWORD_KEY: [u8; 32] = [9; 32];
    const TEST_FILE_KEY: [u8; 32] = [8; 32];
    const TEST_HMAC_SECRET: [u8; 32] = [7; 32];

    fn decode(value: &str) -> Vec<u8> {
        (0..value.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn frozen_unlock_file_round_trip_and_rejections() {
        for (vector, policy) in [
            (
                FROZEN_PASSWORD_ONLY_UNLOCK_FILE_HEX,
                PayloadPolicy::PasswordOnly,
            ),
            (
                FROZEN_PASSWORD_AND_KEY_FILE_UNLOCK_FILE_HEX,
                PayloadPolicy::PasswordAndKeyFile,
            ),
        ] {
            let data = decode(vector);
            let unlock_file = parse_unlock_file(&data).unwrap();
            assert_eq!(unlock_file.payload_policy, policy);
            assert_eq!(serialize_unlock_file(&unlock_file).unwrap(), data);
        }

        let mut malformed = decode(FROZEN_PASSWORD_ONLY_UNLOCK_FILE_HEX);
        malformed[90] = 3;
        assert!(parse_unlock_file(&malformed).is_err());
        let mut trailing = decode(FROZEN_PASSWORD_ONLY_UNLOCK_FILE_HEX);
        trailing.push(0);
        assert!(parse_unlock_file(&trailing).is_err());

        let mut invalid_point = decode(FROZEN_PASSWORD_ONLY_UNLOCK_FILE_HEX);
        let unlock_file = parse_unlock_file(&invalid_point).unwrap();
        let public_key = unlock_file.wrappers[0].public_key;
        let offset = invalid_point
            .windows(public_key.len())
            .position(|window| window == public_key)
            .unwrap();
        invalid_point[offset..offset + public_key.len()].fill(0);
        assert!(parse_unlock_file(&invalid_point).is_err());
    }

    #[test]
    fn frozen_hkdf_and_aes_gcm_values() {
        let slot: [u8; 16] = decode(HKDF_SLOT_HEX).try_into().unwrap();
        let envelope: [u8; 16] = decode(HKDF_ENVELOPE_HEX).try_into().unwrap();
        let secret = Zeroizing::new(decode(HKDF_SECRET_HEX).try_into().unwrap());

        assert_eq!(
            hex(&hkdf(&secret, &envelope, &slot).unwrap()[..]),
            EXPECTED_KEK_HEX
        );

        for (vector, expected_file_key) in [
            (
                FROZEN_PASSWORD_ONLY_UNLOCK_FILE_HEX,
                "0000000000000000000000000000000000000000000000000000000000000000",
            ),
            (
                FROZEN_PASSWORD_AND_KEY_FILE_UNLOCK_FILE_HEX,
                EXPECTED_FILE_KEY_HEX,
            ),
        ] {
            let unlock_file = parse_unlock_file(&decode(vector)).unwrap();
            let wrapper = &unlock_file.wrappers[0];
            let mut crypter = Crypter::new(
                Cipher::aes_256_gcm(),
                Mode::Decrypt,
                &hkdf(&secret, &envelope, &slot).unwrap()[..],
                Some(&wrapper.nonce),
            )
            .unwrap();
            let authenticated = aad(
                unlock_file.payload_policy,
                &unlock_file.envelope_id,
                &wrapper.slot_id,
                &wrapper.credential_id,
                &wrapper.public_key,
                &unlock_file.envelope_salt,
            );
            assert_eq!(authenticated.len(), 190);
            assert_eq!(authenticated[12], unlock_file.payload_policy as u8);
            crypter.aad_update(&authenticated).unwrap();
            crypter.set_tag(&wrapper.ciphertext[64..]).unwrap();
            let mut plaintext = Zeroizing::new([0u8; 64]);
            let count = crypter
                .update(&wrapper.ciphertext[..64], &mut plaintext[..])
                .unwrap();
            crypter.finalize(&mut plaintext[count..]).unwrap();
            assert_eq!(hex(&plaintext[..32]), EXPECTED_PASSWORD_KEY_HEX);
            assert_eq!(hex(&plaintext[32..]), expected_file_key);
        }

        let unlock_file = parse_unlock_file(&decode(FROZEN_PASSWORD_ONLY_UNLOCK_FILE_HEX)).unwrap();
        let wrapper = &unlock_file.wrappers[0];
        let mut crypter = Crypter::new(
            Cipher::aes_256_gcm(),
            Mode::Decrypt,
            &hkdf(&secret, &envelope, &slot).unwrap()[..],
            Some(&wrapper.nonce),
        )
        .unwrap();
        crypter
            .aad_update(&aad(
                PayloadPolicy::PasswordAndKeyFile,
                &unlock_file.envelope_id,
                &wrapper.slot_id,
                &wrapper.credential_id,
                &wrapper.public_key,
                &unlock_file.envelope_salt,
            ))
            .unwrap();
        crypter.set_tag(&wrapper.ciphertext[64..]).unwrap();
        let mut plaintext = Zeroizing::new([0u8; 64]);
        let count = crypter
            .update(&wrapper.ciphertext[..64], &mut plaintext[..])
            .unwrap();
        assert!(crypter.finalize(&mut plaintext[count..]).is_err());
    }

    #[test]
    fn broker_frames_reject_trailing_data() {
        let valid = decode(VALID_CREATE_RESPONSE_HEX);
        assert!(
            parse_create_reply(&parse_response(BROKER_CREATE_OPERATION, &valid).unwrap()).is_ok()
        );

        let mut trailing = valid;
        trailing.push(0);
        assert!(parse_response(BROKER_CREATE_OPERATION, &trailing).is_err());

        let error = decode(ERROR_RESPONSE_HEX);
        assert_eq!(
            parse_response(BROKER_ASSERT_OPERATION, &error).unwrap_err(),
            "broker failed with status 6: bad"
        );
    }

    #[test]
    fn broker_probe_requires_empty_success_payload() {
        let valid = decode(VALID_PROBE_RESPONSE_HEX);
        assert!(
            parse_probe_reply(&parse_response(BROKER_PROBE_OPERATION, &valid).unwrap()).is_ok()
        );

        assert!(parse_probe_reply(&[0]).is_err());
    }

    struct MockBroker {
        private: PKey<openssl::pkey::Private>,
        credential: Vec<u8>,
        public: [u8; 64],
    }
    impl MockBroker {
        fn new() -> Self {
            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
            let key = EcKey::generate(&group).unwrap();
            let mut context = openssl::bn::BigNumContext::new().unwrap();
            let mut x = BigNum::new().unwrap();
            let mut y = BigNum::new().unwrap();
            key.public_key()
                .affine_coordinates_gfp(&group, &mut x, &mut y, &mut context)
                .unwrap();
            let mut public = [0u8; 64];
            public[..32].copy_from_slice(&x.to_vec_padded(32).unwrap());
            public[32..].copy_from_slice(&y.to_vec_padded(32).unwrap());
            Self {
                private: PKey::from_ec_key(key).unwrap(),
                credential: vec![1, 2, 3],
                public,
            }
        }
    }
    impl Broker for MockBroker {
        fn probe(&mut self) -> Result<()> {
            Ok(())
        }

        fn create(&mut self, _: [u8; 32], _: &[u8], _: &str) -> Result<CreateReply> {
            Ok(CreateReply {
                credential_id: self.credential.clone(),
                public_key: self.public,
                flags: REQUIRED_AUTH_DATA_FLAGS,
                credential_protection: CREDENTIAL_PROTECTION_UV_REQUIRED,
            })
        }
        fn assert(
            &mut self,
            client: [u8; 32],
            _: [u8; 32],
            ids: &[Vec<u8>],
            _: &[u8],
        ) -> Result<AssertReply> {
            assert_eq!(ids, std::slice::from_ref(&self.credential));
            let mut auth = hash(MessageDigest::sha256(), RP_ID).unwrap().to_vec();
            auth.extend_from_slice(&[REQUIRED_AUTH_DATA_FLAGS, 0, 0, 0, 0]);

            let mut signer = Signer::new(MessageDigest::sha256(), &self.private).unwrap();
            signer.update(&auth).unwrap();
            signer.update(&client).unwrap();
            Ok(AssertReply {
                selected_credential_id: self.credential.clone(),
                authenticator_data: auth,
                signature: signer.sign_to_vec().unwrap(),
                hmac_secret: Zeroizing::new(TEST_HMAC_SECRET),
            })
        }
    }

    #[test]
    fn mock_broker_enrollment_produces_canonical_wrapper() {
        let mut mock = MockBroker::new();
        let password_key = Zeroizing::new(TEST_PASSWORD_KEY);
        let file_key = Zeroizing::new([0; 32]);
        let mut pin = Zeroizing::new(TEST_PIN.to_vec());
        let unlock_file = enroll_new(
            None,
            PayloadPolicy::PasswordOnly,
            "test key".into(),
            &password_key,
            &file_key,
            &mut pin,
            &mut mock,
        )
        .unwrap();
        assert_eq!(unlock_file.wrappers.len(), 1);
        assert!(parse_unlock_file(&serialize_unlock_file(&unlock_file).unwrap()).is_ok());
    }

    #[test]
    fn append_preserves_existing_wrappers() {
        let existing =
            parse_unlock_file(&decode(FROZEN_PASSWORD_AND_KEY_FILE_UNLOCK_FILE_HEX)).unwrap();
        let original = existing.wrappers.clone();
        let password_key = Zeroizing::new(TEST_PASSWORD_KEY);
        let file_key = Zeroizing::new(TEST_FILE_KEY);
        let mut pin = Zeroizing::new(TEST_PIN.to_vec());
        let mut mock = MockBroker::new();
        let appended = enroll_new(
            Some(existing),
            PayloadPolicy::PasswordAndKeyFile,
            "new key".into(),
            &password_key,
            &file_key,
            &mut pin,
            &mut mock,
        )
        .unwrap();
        assert_eq!(appended.payload_policy, PayloadPolicy::PasswordAndKeyFile);
        assert_eq!(appended.wrappers.len(), 3);
        for wrapper in original {
            assert!(appended.wrappers.contains(&wrapper));
        }

        let mut pin = Zeroizing::new(TEST_PIN.to_vec());
        assert!(
            enroll_new(
                Some(appended),
                PayloadPolicy::PasswordOnly,
                "wrong policy".into(),
                &password_key,
                &Zeroizing::new([0; 32]),
                &mut pin,
                &mut mock,
            )
            .is_err()
        );
    }

    #[test]
    fn key_file_formats_and_xml_checksum_match_keepassxc() {
        let mut directory = std::env::temp_dir();
        directory.push(format!(
            "keepass-fido2-key-file-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let path = directory.join("key file with spaces.keyx");
        let expected: [u8; 32] = std::array::from_fn(|index| index as u8);

        fs::write(&path, expected).unwrap();
        assert_eq!(&load_key_file(&path).unwrap()[..], &expected);

        fs::write(&path, hex(&expected).to_uppercase()).unwrap();
        assert_eq!(&load_key_file(&path).unwrap()[..], &expected);

        let arbitrary = b"arbitrary key file contents that are hashed";
        fs::write(&path, arbitrary).unwrap();
        assert_eq!(&load_key_file(&path).unwrap()[..], &sha256(arbitrary));

        let grown_binary: Vec<u8> = (0u8..33).collect();
        fs::write(&path, &grown_binary).unwrap();
        let mut opened = File::open(&path).unwrap();
        assert_eq!(
            &load_key_file_from_open(&mut opened, 32).unwrap()[..],
            &sha256(&grown_binary)
        );

        let mut grown_hex = hex(&expected).into_bytes();
        grown_hex.push(b'x');
        fs::write(&path, &grown_hex).unwrap();
        let mut opened = File::open(&path).unwrap();
        assert_eq!(
            &load_key_file_from_open(&mut opened, 64).unwrap()[..],
            &sha256(&grown_hex)
        );

        let xml_v1 = format!(
            "<?xml version=\"1.0\"?><KeyFile><Meta><Version>1.00</Version></Meta><Key><Data>{}</Data></Key></KeyFile>",
            base64::encode_block(&expected)
        );
        fs::write(&path, xml_v1).unwrap();
        assert_eq!(&load_key_file(&path).unwrap()[..], &expected);

        let checksum = hex(&sha256(&expected)[..4]).to_uppercase();
        let xml_v2 = format!(
            "<?xml version=\"1.0\"?><KeyFile><Meta><Version>2.0</Version></Meta><Key><Data Hash=\"{checksum}\">\n {} \n</Data></Key></KeyFile>",
            hex(&expected).to_uppercase()
        );
        fs::write(&path, &xml_v2).unwrap();
        assert_eq!(&load_key_file(&path).unwrap()[..], &expected);

        let xml_v2_utf16 = xml_v2.replacen(
            "<?xml version=\"1.0\"?>",
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?>",
            1,
        );
        let mut utf16_le = vec![0xff, 0xfe];
        for code_unit in xml_v2_utf16.encode_utf16() {
            utf16_le.extend_from_slice(&code_unit.to_le_bytes());
        }
        fs::write(&path, utf16_le).unwrap();
        assert_eq!(&load_key_file(&path).unwrap()[..], &expected);

        let mut utf16_be = vec![0xfe, 0xff];
        for code_unit in xml_v2_utf16.encode_utf16() {
            utf16_be.extend_from_slice(&code_unit.to_be_bytes());
        }
        fs::write(&path, utf16_be).unwrap();
        assert_eq!(&load_key_file(&path).unwrap()[..], &expected);

        fs::write(&path, xml_v2.replace(&checksum, "00000000")).unwrap();
        assert!(load_key_file(&path).is_err());
        fs::write(
            &path,
            "<KeyFile><Meta><Version>1.0</Version></Meta><Key><Data>not-base64</Data></Key></KeyFile>",
        )
        .unwrap();
        assert!(load_key_file(&path).is_err());

        let malformed_xml = b"<KeyFile><Meta><Version>1.0</Version>";
        fs::write(&path, malformed_xml).unwrap();
        assert_eq!(&load_key_file(&path).unwrap()[..], &sha256(malformed_xml));
        let empty_xml = b"<KeyFile><Meta><Version>1.0</Version></Meta><Key></Key></KeyFile>";
        fs::write(&path, empty_xml).unwrap();
        assert_eq!(&load_key_file(&path).unwrap()[..], &sha256(empty_xml));

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn xml_key_file_structure_and_raw_key_sizing_match_keepassxc() {
        let mut directory = std::env::temp_dir();
        directory.push(format!(
            "keepass-fido2-xml-structure-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let path = directory.join("structure.keyx");
        let key: [u8; 32] = std::array::from_fn(|index| index as u8);
        let encoded = base64::encode_block(&key);

        let misplaced_version =
            format!("<KeyFile><Version>1.0</Version><Key><Data>{encoded}</Data></Key></KeyFile>");
        fs::write(&path, &misplaced_version).unwrap();
        assert_eq!(
            &load_key_file(&path).unwrap()[..],
            &sha256(misplaced_version.as_bytes())
        );

        let misplaced_data =
            format!("<KeyFile><Meta><Version>1.0</Version><Data>{encoded}</Data></Meta></KeyFile>");
        fs::write(&path, &misplaced_data).unwrap();
        assert_eq!(
            &load_key_file(&path).unwrap()[..],
            &sha256(misplaced_data.as_bytes())
        );

        let nested_data = "<KeyFile><Meta><Version>1.0</Version></Meta><Key><Data><Nested/></Data></Key></KeyFile>";
        fs::write(&path, nested_data).unwrap();
        assert_eq!(
            &load_key_file(&path).unwrap()[..],
            &sha256(nested_data.as_bytes())
        );

        let multiple_roots = format!(
            "<KeyFile><Meta><Version>1.0</Version></Meta><Key><Data>{encoded}</Data></Key></KeyFile><KeyFile/>"
        );
        fs::write(&path, &multiple_roots).unwrap();
        assert_eq!(
            &load_key_file(&path).unwrap()[..],
            &sha256(multiple_roots.as_bytes())
        );

        let key_before_meta = format!(
            "<KeyFile><Key><Data>{encoded}</Data></Key><Meta><Version>1.0</Version></Meta></KeyFile>"
        );
        fs::write(&path, key_before_meta).unwrap();
        assert_eq!(
            load_key_file(&path).unwrap_err(),
            "unexpected XML key file data"
        );

        let short = [1u8, 2, 3];
        let short_xml = format!(
            "<KeyFile><Unknown><Version>wrong</Version><Data>bad</Data></Unknown><Meta><Version>1.0</Version></Meta><Key><Data>{}</Data></Key></KeyFile>",
            base64::encode_block(&short)
        );
        fs::write(&path, short_xml).unwrap();
        let mut short_expected = [0u8; 32];
        short_expected[..short.len()].copy_from_slice(&short);
        assert_eq!(&load_key_file(&path).unwrap()[..], &short_expected);

        let version_after_data = format!(
            "<KeyFile><Meta><Version>1.0</Version></Meta><Key><Data>{}</Data></Key><Meta><Version>2.0</Version></Meta></KeyFile>",
            base64::encode_block(&short)
        );
        fs::write(&path, version_after_data).unwrap();
        assert_eq!(&load_key_file(&path).unwrap()[..], &short_expected);

        let last_v1_data = format!(
            "<KeyFile><Meta><Version>1.0</Version></Meta><Key><Data>{}</Data><Data>{encoded}</Data></Key></KeyFile>",
            base64::encode_block(&short)
        );
        fs::write(&path, last_v1_data).unwrap();
        assert_eq!(&load_key_file(&path).unwrap()[..], &key);

        let long: Vec<u8> = (0u8..40).collect();
        let long_checksum = hex(&sha256(&long)[..4]).to_uppercase();
        let long_xml = format!(
            "<KeyFile><Meta><Version>2.0</Version></Meta><Key><Data Hash=\"{long_checksum}\">{}</Data></Key></KeyFile>",
            hex(&long)
        );
        fs::write(&path, long_xml).unwrap();
        assert_eq!(&load_key_file(&path).unwrap()[..], &long[..32]);

        let ordered_versions = format!(
            "<KeyFile><Meta><Version>1.0</Version></Meta><Key><Data>{}</Data></Key><Meta><Version>2.0</Version></Meta><Key><Data Hash=\"{long_checksum}\">{}</Data></Key></KeyFile>",
            base64::encode_block(&short),
            hex(&long)
        );
        fs::write(&path, ordered_versions).unwrap();
        assert_eq!(&load_key_file(&path).unwrap()[..], &long[..32]);

        let unsupported_after_data = format!(
            "<KeyFile><Meta><Version>1.0</Version></Meta><Key><Data>{encoded}</Data></Key><Meta><Version>3.0</Version></Meta></KeyFile>"
        );
        fs::write(&path, unsupported_after_data).unwrap();
        assert!(load_key_file(&path).is_err());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn bounded_read_and_label_display_are_safe() {
        assert!(read_limited(std::io::Cursor::new(vec![0; 2]), 1, "test").is_err());
        assert_eq!(display_label("label\n\u{1b}[2J"), "label\\n\\u{1b}[2J");
        assert_eq!(
            parent_directory(Path::new("relative.kpxc-fido2")),
            Path::new(".")
        );
        assert_eq!(
            VERIFICATION_INSTRUCTION,
            "FIDO2 unlock file published. Verify immediately by unlocking the database in the modified KeePassXC."
        );
    }

    #[test]
    fn broker_child_guard_reaps_after_oversized_output() {
        let mut child = BrokerChild(Some(
            Command::new("/bin/sh")
                .args(["-c", "head -c 2 /dev/zero; sleep 30"])
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        ));
        let stdout = child.child().stdout.take().unwrap();
        assert!(read_limited(stdout, 1, "test broker output").is_err());
        drop(child);
    }

    #[test]
    fn atomic_create_does_not_clobber_and_final_wrapper_cannot_be_removed() {
        let mut directory = std::env::temp_dir();
        directory.push(format!("keepass-fido2-enroll-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let path = directory.join("envelope.kpxc-fido2");
        let mut unlock_file =
            parse_unlock_file(&decode(FROZEN_PASSWORD_ONLY_UNLOCK_FILE_HEX)).unwrap();
        assert!(read_unlock_file(&directory).is_err());
        create_unlock_file(&path, &unlock_file).unwrap();
        let original = fs::read(&path).unwrap();
        assert!(create_unlock_file(&path, &unlock_file).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        let first_slot = unlock_file.wrappers[0].slot_id;
        remove_wrapper(&mut unlock_file, first_slot).unwrap();
        replace_unlock_file(&path, &unlock_file).unwrap();
        assert_eq!(read_unlock_file(&path).unwrap(), unlock_file);
        let final_slot = unlock_file.wrappers[0].slot_id;
        assert!(remove_wrapper(&mut unlock_file, final_slot).is_err());
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn unlock_file_reads_reject_symlinks() {
        let mut directory = std::env::temp_dir();
        directory.push(format!(
            "keepass-fido2-unlock-file-symlink-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let target = directory.join("target.kpxc-fido2");
        let link = directory.join("link.kpxc-fido2");
        let broken = directory.join("broken.kpxc-fido2");
        let unlock_file = parse_unlock_file(&decode(FROZEN_PASSWORD_ONLY_UNLOCK_FILE_HEX)).unwrap();
        create_unlock_file(&target, &unlock_file).unwrap();
        symlink(&target, &link).unwrap();
        symlink(directory.join("missing.kpxc-fido2"), &broken).unwrap();

        assert!(read_unlock_file(&link).is_err());
        assert!(LockedFido2UnlockFileUpdate::open(&link).is_err());
        assert!(create_unlock_file(&link, &unlock_file).is_err());
        assert!(read_unlock_file(&broken).is_err());
        assert!(create_unlock_file(&broken, &unlock_file).is_err());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn locked_unlock_file_update_serializes_and_detects_conflicts() {
        let mut directory = std::env::temp_dir();
        directory.push(format!(
            "keepass-fido2-unlock-file-lock-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let path = directory.join("locked.kpxc-fido2");
        let original = decode(FROZEN_PASSWORD_ONLY_UNLOCK_FILE_HEX);
        fs::write(&path, &original).unwrap();

        let locked = LockedFido2UnlockFileUpdate::open(&path).unwrap();
        let (competing, _) = open_unlock_file(&path).unwrap();
        assert_ne!(
            unsafe { libc::flock(competing.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB,) },
            0
        );
        drop(competing);
        let mut changed = original.clone();
        changed[14] ^= 1;
        fs::write(&path, changed).unwrap();
        assert!(locked.commit().is_err());

        fs::write(&path, &original).unwrap();
        let locked = LockedFido2UnlockFileUpdate::open(&path).unwrap();
        let replaced = directory.join("replaced.kpxc-fido2");
        fs::rename(&path, &replaced).unwrap();
        fs::write(&path, &original).unwrap();
        assert!(locked.commit().is_err());

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn post_publish_failures_only_warn() {
        struct FailingWriter;
        impl Write for FailingWriter {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("simulated warning failure"))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("simulated warning failure"))
            }
        }

        let error = std::io::Error::other("simulated post-publish failure");
        let mut output = Vec::new();
        write_post_publish_warning(&mut output, "could not finish simulated cleanup", &error);
        assert_eq!(
            String::from_utf8(output).unwrap(),
            "warning: FIDO2 unlock file was published but could not finish simulated cleanup: simulated post-publish failure\n"
        );
        write_post_publish_warning(
            &mut FailingWriter,
            "could not finish simulated cleanup",
            &error,
        );
    }

    #[test]
    fn read_unlock_file_rejects_fifo_without_blocking() {
        let mut directory = std::env::temp_dir();
        directory.push(format!(
            "keepass-fido2-enroll-fifo-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir(&directory).unwrap();
        let fifo = directory.join("unlock-file.fifo");
        let path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        let result = read_unlock_file(&fifo);
        fs::remove_file(&fifo).unwrap();
        fs::remove_dir(&directory).unwrap();
        assert!(result.is_err());
    }
}
