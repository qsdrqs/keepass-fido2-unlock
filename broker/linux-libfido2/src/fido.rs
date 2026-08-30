//! Narrow safe wrapper around the libfido2 calls required by the broker.
//!
//! Every non-null libfido2 allocation is owned by one RAII wrapper and freed by
//! its `Drop` implementation. Request slices and C strings remain alive for the
//! complete duration of each FFI call. Borrowed response pointers are validated
//! and copied before their owning libfido2 object is dropped. No raw pointer is
//! stored outside this module.

use std::ffi::{CStr, CString};
use std::fmt;
use std::mem::MaybeUninit;
use std::ptr;
use std::slice;
use std::sync::atomic::{AtomicBool, Ordering};

use libfido2_sys as sys;
use zeroize::Zeroizing;

use crate::protocol::{AssertRequest, AssertResponse, CreateRequest, CreateResponse, Status};

const DEVICE_SLOTS: usize = 2;
const OPERATION_TIMEOUT_MS: i32 = 60_000;
const ES256_PUBLIC_KEY_SIZE: usize = 64;
const HMAC_SECRET_SIZE: usize = 32;
const MAX_CREDENTIAL_ID_SIZE: usize = 1024;
const MAX_AUTH_DATA_SIZE: usize = 2048;
const MAX_SIGNATURE_SIZE: usize = 256;
const REQUIRED_AUTH_DATA_FLAGS: u8 =
    (sys::CTAP_AUTHDATA_USER_PRESENT | sys::CTAP_AUTHDATA_USER_VERIFIED) as u8;

static CANCELLATION_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Error returned by the broker's safe libfido2 operations.
pub enum Error {
    /// SIGUSR1 requested cancellation of the current operation.
    Cancelled,
    /// Device discovery found no authenticator.
    NoDevice,
    /// Device discovery found more than one authenticator.
    MultipleDevices,
    /// The sole authenticator lacks a required capability.
    UnsupportedDevice,
    /// An internal invariant or external response failed validation.
    InvalidResponse(&'static str),
    /// A libfido2 call failed with its original operation and error details.
    Library {
        /// Name of the libfido2 operation that failed.
        operation: &'static str,
        /// Original libfido2 status code.
        code: i32,
        /// Owned description copied from libfido2.
        description: String,
    },
}

impl Error {
    /// Maps an internal or libfido2 failure to the stable protocol status set.
    pub fn status(&self) -> Status {
        match self {
            Self::Cancelled => Status::Cancelled,
            Self::NoDevice => Status::NoDevice,
            Self::MultipleDevices => Status::MultipleDevices,
            Self::UnsupportedDevice => Status::UnsupportedDevice,
            Self::InvalidResponse(_) => Status::Internal,
            Self::Library { code, .. } => map_status(*code),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("operation cancelled"),
            Self::NoDevice => formatter.write_str("no FIDO device found"),
            Self::MultipleDevices => formatter.write_str("connect exactly one FIDO device"),
            Self::UnsupportedDevice => {
                formatter.write_str("device lacks required FIDO2, PIN, or credProtect support")
            }
            Self::InvalidResponse(message) => formatter.write_str(message),
            Self::Library {
                operation,
                description,
                ..
            } => write!(formatter, "{operation}: {description}"),
        }
    }
}

/// Validates that exactly one supported FIDO2 device is available.
///
/// Opening the device applies the same capability and timeout policy used by
/// credential creation and assertion operations.
pub fn probe() -> Result<(), Error> {
    let devices = DeviceInfoList::manifest()?;
    let _device = Device::open(devices.only()?)?;
    Ok(())
}

/// Creates and verifies an ES256 credential with required UV and hmac-secret policy.
///
/// Authenticator output is copied into owned Rust values only after attestation,
/// flags, algorithm, and credential-protection policy have been verified.
pub fn create(request: &CreateRequest) -> Result<CreateResponse, Error> {
    let devices = DeviceInfoList::manifest()?;
    let device = Device::open(devices.only()?)?;
    let credential = Credential::new()?;
    let pin = secret_cstring(&request.pin)?;
    let rp_id = cstring(&request.rp_id, "invalid RP ID")?;
    let rp_name = cstring(&request.rp_name, "invalid RP name")?;
    let user_name = cstring(&request.user_name, "invalid user name")?;
    let user_display_name = cstring(&request.user_display_name, "invalid display name")?;

    // SAFETY: all libfido2 handles are non-null RAII-owned allocations. Every
    // input pointer references storage that outlives these calls, and borrowed
    // credential outputs are copied before `credential` is dropped.
    let (flags, credential_id, public_key) = unsafe {
        check(
            "fido_cred_set_type",
            sys::fido_cred_set_type(credential.pointer, sys::COSE_ES256),
        )?;
        check(
            "fido_cred_set_clientdata_hash",
            sys::fido_cred_set_clientdata_hash(
                credential.pointer,
                request.client_data_hash.as_ptr(),
                request.client_data_hash.len(),
            ),
        )?;
        check(
            "fido_cred_set_rp",
            sys::fido_cred_set_rp(credential.pointer, rp_id.as_ptr(), rp_name.as_ptr()),
        )?;
        check(
            "fido_cred_set_user",
            sys::fido_cred_set_user(
                credential.pointer,
                request.user_id.as_ptr(),
                request.user_id.len(),
                user_name.as_ptr(),
                user_display_name.as_ptr(),
                ptr::null(),
            ),
        )?;

        check(
            "fido_cred_set_rk",
            sys::fido_cred_set_rk(credential.pointer, sys::fido_opt_t_FIDO_OPT_FALSE),
        )?;
        check(
            "fido_cred_set_uv",
            sys::fido_cred_set_uv(credential.pointer, sys::fido_opt_t_FIDO_OPT_TRUE),
        )?;
        check(
            "fido_cred_set_extensions",
            sys::fido_cred_set_extensions(credential.pointer, sys::FIDO_EXT_HMAC_SECRET),
        )?;
        check(
            "fido_cred_set_prot",
            sys::fido_cred_set_prot(credential.pointer, sys::FIDO_CRED_PROT_UV_REQUIRED),
        )?;

        check(
            "fido_dev_make_cred",
            sys::fido_dev_make_cred(device.pointer, credential.pointer, pin.as_ptr()),
        )?;

        let flags = sys::fido_cred_flags(credential.pointer);
        if flags & REQUIRED_AUTH_DATA_FLAGS != REQUIRED_AUTH_DATA_FLAGS
            || sys::fido_cred_type(credential.pointer) != sys::COSE_ES256
            || sys::fido_cred_prot(credential.pointer) != sys::FIDO_CRED_PROT_UV_REQUIRED
        {
            return Err(Error::InvalidResponse(
                "credential response lacks required type, UP, UV, or credProtect policy",
            ));
        }

        let format_pointer = sys::fido_cred_fmt(credential.pointer);
        if format_pointer.is_null() || CStr::from_ptr(format_pointer).to_bytes() == b"none" {
            return Err(Error::InvalidResponse(
                "credential response has no verifiable attestation",
            ));
        }

        let verification = if sys::fido_cred_x5c_ptr(credential.pointer).is_null() {
            sys::fido_cred_verify_self(credential.pointer)
        } else {
            sys::fido_cred_verify(credential.pointer)
        };
        check("credential verification", verification)?;

        let credential_id = copy_bytes(
            sys::fido_cred_id_ptr(credential.pointer),
            sys::fido_cred_id_len(credential.pointer),
            MAX_CREDENTIAL_ID_SIZE,
            "invalid credential ID",
        )?;
        let public_key = copy_array::<ES256_PUBLIC_KEY_SIZE>(
            sys::fido_cred_pubkey_ptr(credential.pointer),
            sys::fido_cred_pubkey_len(credential.pointer),
            "invalid ES256 public key",
        )?;
        (flags, credential_id, public_key)
    };

    Ok(CreateResponse {
        credential_id,
        public_key,
        flags,
        credential_protection: sys::FIDO_CRED_PROT_UV_REQUIRED as u8,
    })
}

/// Gets one assertion and copies its signed data and hmac-secret output.
///
/// SIGUSR1 is reserved as cancellation for the duration of this one-shot
/// process. The returned credential must belong to the request allow-list.
pub fn assert(request: &AssertRequest) -> Result<AssertResponse, Error> {
    let cancellation = Cancellation::install()?;
    let devices = DeviceInfoList::manifest()?;
    let device = Device::open(devices.only()?)?;
    device.set_sigmask(cancellation.io_mask())?;
    let assertion = Assertion::new()?;
    let pin = secret_cstring(&request.pin)?;
    let rp_id = cstring(&request.rp_id, "invalid RP ID")?;

    // SAFETY: `device` and `assertion` own valid libfido2 handles. Request and
    // CString storage remains alive through the transaction, and every borrowed
    // assertion field is copied before its owner is freed.
    let (selected_credential_id, authenticator_data, signature, hmac_secret) = unsafe {
        check(
            "fido_assert_set_clientdata_hash",
            sys::fido_assert_set_clientdata_hash(
                assertion.pointer,
                request.client_data_hash.as_ptr(),
                request.client_data_hash.len(),
            ),
        )?;
        check(
            "fido_assert_set_rp",
            sys::fido_assert_set_rp(assertion.pointer, rp_id.as_ptr()),
        )?;
        for credential_id in &request.credential_ids {
            check(
                "fido_assert_allow_cred",
                sys::fido_assert_allow_cred(
                    assertion.pointer,
                    credential_id.as_ptr(),
                    credential_id.len(),
                ),
            )?;
        }

        check(
            "fido_assert_set_extensions",
            sys::fido_assert_set_extensions(assertion.pointer, sys::FIDO_EXT_HMAC_SECRET),
        )?;
        check(
            "fido_assert_set_hmac_salt",
            sys::fido_assert_set_hmac_salt(
                assertion.pointer,
                request.hmac_salt.as_ptr(),
                request.hmac_salt.len(),
            ),
        )?;

        check(
            "fido_assert_set_up",
            sys::fido_assert_set_up(assertion.pointer, sys::fido_opt_t_FIDO_OPT_TRUE),
        )?;
        check(
            "fido_assert_set_uv",
            sys::fido_assert_set_uv(assertion.pointer, sys::fido_opt_t_FIDO_OPT_TRUE),
        )?;

        if cancellation.requested() {
            return Err(Error::Cancelled);
        }

        let code = sys::fido_dev_get_assert(device.pointer, assertion.pointer, pin.as_ptr());
        if code != sys::FIDO_OK {
            device.cancel();
            if cancellation.requested() {
                return Err(Error::Cancelled);
            }
            check("fido_dev_get_assert", code)?;
        }

        if sys::fido_assert_count(assertion.pointer) != 1 {
            return Err(Error::InvalidResponse("expected exactly one assertion"));
        }

        let selected_credential_id = copy_bytes(
            sys::fido_assert_id_ptr(assertion.pointer, 0),
            sys::fido_assert_id_len(assertion.pointer, 0),
            MAX_CREDENTIAL_ID_SIZE,
            "missing or invalid returned credential ID",
        )?;
        validate_selected_credential_id(&request.credential_ids, &selected_credential_id)?;

        let flags = sys::fido_assert_flags(assertion.pointer, 0);
        if flags & REQUIRED_AUTH_DATA_FLAGS != REQUIRED_AUTH_DATA_FLAGS {
            return Err(Error::InvalidResponse(
                "assertion lacks required UP or UV flags",
            ));
        }

        let authenticator_data = copy_bytes(
            sys::fido_assert_authdata_raw_ptr(assertion.pointer, 0),
            sys::fido_assert_authdata_raw_len(assertion.pointer, 0),
            MAX_AUTH_DATA_SIZE,
            "invalid authenticator data",
        )?;
        let signature = copy_bytes(
            sys::fido_assert_sig_ptr(assertion.pointer, 0),
            sys::fido_assert_sig_len(assertion.pointer, 0),
            MAX_SIGNATURE_SIZE,
            "invalid assertion signature",
        )?;

        let hmac_secret = Zeroizing::new(copy_array::<HMAC_SECRET_SIZE>(
            sys::fido_assert_hmac_secret_ptr(assertion.pointer, 0),
            sys::fido_assert_hmac_secret_len(assertion.pointer, 0),
            "invalid hmac-secret",
        )?);
        (
            selected_credential_id,
            authenticator_data,
            signature,
            hmac_secret,
        )
    };

    Ok(AssertResponse {
        selected_credential_id,
        authenticator_data,
        signature,
        hmac_secret,
    })
}

fn check(operation: &'static str, code: i32) -> Result<(), Error> {
    if code == sys::FIDO_OK {
        return Ok(());
    }

    // SAFETY: libfido2 accepts every integer error code and returns either a
    // null pointer or a process-static NUL-terminated description.
    let description_pointer = unsafe { sys::fido_strerr(code) };
    let description = if description_pointer.is_null() {
        format!("libfido2 error {code}")
    } else {
        // SAFETY: the pointer was checked for null and is owned by libfido2 as
        // immutable process-static storage.
        unsafe { CStr::from_ptr(description_pointer) }
            .to_string_lossy()
            .into_owned()
    };
    Err(Error::Library {
        operation,
        code,
        description,
    })
}

// Only errors with a stable public meaning receive a specific protocol status.
// All other libfido2 codes fail closed as Internal without exposing ABI values.
fn map_status(code: i32) -> Status {
    match code {
        value if value == sys::FIDO_ERR_PIN_INVALID => Status::PinInvalid,

        value
            if value == sys::FIDO_ERR_PIN_BLOCKED
                || value == sys::FIDO_ERR_PIN_AUTH_BLOCKED
                || value == sys::FIDO_ERR_UV_BLOCKED =>
        {
            Status::PinBlocked
        }

        value
            if value == sys::FIDO_ERR_TIMEOUT
                || value == sys::FIDO_ERR_USER_ACTION_TIMEOUT
                || value == sys::FIDO_ERR_ACTION_TIMEOUT =>
        {
            Status::Timeout
        }

        value if value == sys::FIDO_ERR_KEEPALIVE_CANCEL => Status::Cancelled,
        value if value == sys::FIDO_ERR_OPERATION_DENIED || value == sys::FIDO_ERR_NOT_ALLOWED => {
            Status::Denied
        }
        value if value == sys::FIDO_ERR_NO_CREDENTIALS => Status::NoCredential,

        value
            if value == sys::FIDO_ERR_UNSUPPORTED_OPTION
                || value == sys::FIDO_ERR_UNSUPPORTED_EXTENSION
                || value == sys::FIDO_ERR_UNSUPPORTED_ALGORITHM =>
        {
            Status::UnsupportedDevice
        }
        _ => Status::Internal,
    }
}

fn cstring(value: &str, message: &'static str) -> Result<CString, Error> {
    CString::new(value).map_err(|_| Error::InvalidResponse(message))
}

fn secret_cstring(value: &[u8]) -> Result<Zeroizing<CString>, Error> {
    CString::new(value)
        .map(Zeroizing::new)
        .map_err(|_| Error::InvalidResponse("invalid PIN"))
}

fn validate_selected_credential_id(
    credential_ids: &[Vec<u8>],
    selected_credential_id: &[u8],
) -> Result<(), Error> {
    if selected_credential_id.is_empty() || selected_credential_id.len() > MAX_CREDENTIAL_ID_SIZE {
        return Err(Error::InvalidResponse(
            "missing or invalid returned credential ID",
        ));
    }
    if !credential_ids
        .iter()
        .any(|credential_id| credential_id == selected_credential_id)
    {
        return Err(Error::InvalidResponse(
            "returned credential ID is not allowed",
        ));
    }
    Ok(())
}

fn copy_bytes(
    pointer: *const u8,
    length: usize,
    maximum: usize,
    message: &'static str,
) -> Result<Vec<u8>, Error> {
    // Reject the pointer-length pair before constructing a Rust slice. Copying
    // detaches the result from the lifetime of its libfido2 owner.
    if pointer.is_null() || length == 0 || length > maximum {
        return Err(Error::InvalidResponse(message));
    }
    // SAFETY: all call sites pass a libfido2 output pointer whose non-zero
    // length was returned by the same live owner object.
    Ok(unsafe { slice::from_raw_parts(pointer, length) }.to_vec())
}

fn copy_array<const SIZE: usize>(
    pointer: *const u8,
    length: usize,
    message: &'static str,
) -> Result<[u8; SIZE], Error> {
    // Fixed-size outputs are accepted only at their exact protocol length.
    if pointer.is_null() || length != SIZE {
        return Err(Error::InvalidResponse(message));
    }
    let mut value = [0u8; SIZE];
    // SAFETY: all call sites pass a libfido2 output pointer whose exact length
    // was returned by the same live owner object.
    value.copy_from_slice(unsafe { slice::from_raw_parts(pointer, length) });
    Ok(value)
}

extern "C" fn cancellation_handler(_signal: libc::c_int) {
    // Relaxed ordering is sufficient because this flag communicates only the
    // cancellation event and does not publish any accompanying memory.
    CANCELLATION_REQUESTED.store(true, Ordering::Relaxed);
}

/// Process-lifetime ownership of the SIGUSR1 cancellation policy.
///
/// The broker handles one request and exits, so the prior handler and signal
/// mask do not need restoration. SIGUSR1 stays blocked outside libfido2 I/O;
/// `io_mask` unblocks it only while libfido2 waits on the authenticator.
struct Cancellation {
    io_mask: libc::sigset_t,
}

impl Cancellation {
    fn install() -> Result<Self, Error> {
        let mut cancellation_set = MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: `sigemptyset` initializes the complete sigset_t object through
        // the valid writable pointer supplied here.
        if unsafe { libc::sigemptyset(cancellation_set.as_mut_ptr()) } != 0 {
            return Err(Error::InvalidResponse("sigemptyset failed"));
        }
        // SAFETY: the preceding successful call initialized `cancellation_set`.
        let mut cancellation_set = unsafe { cancellation_set.assume_init() };
        // SAFETY: the set is initialized and SIGUSR1 is a valid signal number.
        if unsafe { libc::sigaddset(&mut cancellation_set, libc::SIGUSR1) } != 0 {
            return Err(Error::InvalidResponse("sigaddset failed"));
        }

        // SAFETY: `cancellation_set` is initialized and remains live for this
        // call. A null old-mask pointer is explicitly permitted.
        if unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &cancellation_set, ptr::null_mut()) }
            != 0
        {
            return Err(Error::InvalidResponse("pthread_sigmask failed"));
        }
        // Blocking before handler installation prevents SIGUSR1 from racing the
        // reset or arriving before the handler is ready.
        CANCELLATION_REQUESTED.store(false, Ordering::Relaxed);

        let mut action = MaybeUninit::<libc::sigaction>::zeroed();
        // SAFETY: the zeroed sigaction has writable storage, and sigemptyset
        // initializes its handler mask before the structure is installed.
        if unsafe { libc::sigemptyset(&mut (*action.as_mut_ptr()).sa_mask) } != 0 {
            return Err(Error::InvalidResponse("sigemptyset failed"));
        }
        // SAFETY: the structure was zero-initialized and its mask initialized.
        // The handler has C ABI, does only a lock-free atomic store, and remains
        // valid for the lifetime of this one-shot process.
        unsafe {
            (*action.as_mut_ptr()).sa_sigaction = cancellation_handler as *const () as usize;
            (*action.as_mut_ptr()).sa_flags = 0;
            if libc::sigaction(libc::SIGUSR1, action.as_ptr(), ptr::null_mut()) != 0 {
                return Err(Error::InvalidResponse("sigaction failed"));
            }
        }

        let mut blocked_mask = MaybeUninit::<libc::sigset_t>::uninit();
        // SAFETY: a null new-mask pointer queries the calling thread's current
        // mask into the valid writable old-mask pointer.
        if unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, ptr::null(), blocked_mask.as_mut_ptr())
        } != 0
        {
            return Err(Error::InvalidResponse("pthread_sigmask failed"));
        }
        // SAFETY: the successful pthread_sigmask call initialized the mask.
        let mut io_mask = unsafe { blocked_mask.assume_init() };
        // SAFETY: the mask is initialized and SIGUSR1 is a valid signal number.
        if unsafe { libc::sigdelset(&mut io_mask, libc::SIGUSR1) } != 0 {
            return Err(Error::InvalidResponse("sigdelset failed"));
        }

        Ok(Self { io_mask })
    }

    fn io_mask(&self) -> &libc::sigset_t {
        &self.io_mask
    }

    fn requested(&self) -> bool {
        CANCELLATION_REQUESTED.load(Ordering::Relaxed)
    }
}

/// RAII owner for a libfido2 device-information allocation.
struct DeviceInfoList {
    pointer: *mut sys::fido_dev_info_t,
    count: usize,
}

impl DeviceInfoList {
    /// Discovers and requires exactly one connected FIDO device.
    fn manifest() -> Result<Self, Error> {
        // SAFETY: global initialization has no pointer preconditions and is
        // idempotent for each one-shot broker process.
        unsafe { sys::fido_init(sys::FIDO_DISABLE_U2F_FALLBACK) };

        // SAFETY: the requested list size is non-zero and retained for the
        // matching free call in `Drop`.
        let pointer = unsafe { sys::fido_dev_info_new(DEVICE_SLOTS) };
        if pointer.is_null() {
            return Err(Error::InvalidResponse("fido_dev_info_new failed"));
        }

        let mut list = Self { pointer, count: 0 };

        // SAFETY: `list.pointer` owns DEVICE_SLOTS entries and `list.count` is
        // valid writable storage for the duration of the call.
        check("fido_dev_info_manifest", unsafe {
            sys::fido_dev_info_manifest(list.pointer, DEVICE_SLOTS, &mut list.count)
        })?;

        match list.count {
            0 => Err(Error::NoDevice),
            1 => Ok(list),
            _ => Err(Error::MultipleDevices),
        }
    }

    fn only(&self) -> Result<*const sys::fido_dev_info_t, Error> {
        // SAFETY: manifest succeeded with exactly one populated entry, and the
        // returned pointer cannot outlive `self` at its only call sites.
        let pointer = unsafe { sys::fido_dev_info_ptr(self.pointer, 0) };
        if pointer.is_null() {
            Err(Error::InvalidResponse("invalid FIDO device information"))
        } else {
            Ok(pointer)
        }
    }
}

impl Drop for DeviceInfoList {
    fn drop(&mut self) {
        // SAFETY: this wrapper uniquely owns the list allocated with the same
        // DEVICE_SLOTS value and never frees it elsewhere.
        unsafe { sys::fido_dev_info_free(&mut self.pointer, DEVICE_SLOTS) };
    }
}

/// RAII owner for one libfido2 device handle and its open state.
struct Device {
    pointer: *mut sys::fido_dev_t,
    open: bool,
}

impl Device {
    /// Opens a FIDO2 device and validates the capabilities required by A2.
    fn open(info: *const sys::fido_dev_info_t) -> Result<Self, Error> {
        // SAFETY: `info` is a non-null entry borrowed from a live manifest;
        // libfido2 copies the information into the new device handle.
        let pointer = unsafe { sys::fido_dev_new_with_info(info) };
        if pointer.is_null() {
            return Err(Error::InvalidResponse("fido_dev_new_with_info failed"));
        }

        let mut device = Self {
            pointer,
            open: false,
        };
        // SAFETY: `device.pointer` is a non-null handle uniquely owned by this
        // wrapper and has not been opened yet.
        check("fido_dev_open_with_info", unsafe {
            sys::fido_dev_open_with_info(device.pointer)
        })?;
        device.open = true;

        // SAFETY: these read-only capability queries accept any open device
        // handle and do not retain references.
        let supported = unsafe {
            sys::fido_dev_is_fido2(device.pointer)
                && sys::fido_dev_has_pin(device.pointer)
                && sys::fido_dev_supports_cred_prot(device.pointer)
        };
        if !supported {
            return Err(Error::UnsupportedDevice);
        }

        // SAFETY: the handle remains open and the timeout is a valid positive
        // millisecond value.
        check("fido_dev_set_timeout", unsafe {
            sys::fido_dev_set_timeout(device.pointer, OPERATION_TIMEOUT_MS)
        })?;
        Ok(device)
    }

    fn set_sigmask(&self, mask: &libc::sigset_t) -> Result<(), Error> {
        // SAFETY: `self.pointer` is an open, uniquely owned device. libc and
        // libfido2 use the same platform sigset_t ABI, and `mask` remains live
        // until after this device is closed.
        check("fido_dev_set_sigmask", unsafe {
            sys::fido_dev_set_sigmask(
                self.pointer,
                ptr::from_ref(mask).cast::<sys::fido_sigset_t>(),
            )
        })
    }

    unsafe fn cancel(&self) {
        // SAFETY: the caller invokes this only on the same thread that owns the
        // open device, after fido_dev_get_assert has returned unsuccessfully.
        unsafe {
            let _ = sys::fido_dev_cancel(self.pointer);
        }
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        if self.open {
            // SAFETY: this wrapper uniquely owns an open device handle. Close
            // is best-effort because Drop cannot report an error.
            unsafe {
                sys::fido_dev_close(self.pointer);
            }
        }
        // SAFETY: the pointer was allocated by libfido2 and is uniquely owned;
        // `fido_dev_free` also accepts the post-close handle.
        unsafe { sys::fido_dev_free(&mut self.pointer) };
    }
}

/// RAII owner for a libfido2 credential object.
struct Credential {
    pointer: *mut sys::fido_cred_t,
}

impl Credential {
    fn new() -> Result<Self, Error> {
        // SAFETY: allocation has no preconditions; a non-null result becomes
        // uniquely owned by the returned wrapper.
        let pointer = unsafe { sys::fido_cred_new() };
        if pointer.is_null() {
            Err(Error::InvalidResponse("fido_cred_new failed"))
        } else {
            Ok(Self { pointer })
        }
    }
}

impl Drop for Credential {
    fn drop(&mut self) {
        // SAFETY: this wrapper uniquely owns the libfido2 credential pointer.
        unsafe { sys::fido_cred_free(&mut self.pointer) };
    }
}

/// RAII owner for a libfido2 assertion object.
struct Assertion {
    pointer: *mut sys::fido_assert_t,
}

impl Assertion {
    fn new() -> Result<Self, Error> {
        // SAFETY: allocation has no preconditions; a non-null result becomes
        // uniquely owned by the returned wrapper.
        let pointer = unsafe { sys::fido_assert_new() };
        if pointer.is_null() {
            Err(Error::InvalidResponse("fido_assert_new failed"))
        } else {
            Ok(Self { pointer })
        }
    }
}

impl Drop for Assertion {
    fn drop(&mut self) {
        // SAFETY: this wrapper uniquely owns the assertion. libfido2 clears the
        // internally stored hmac-secret while freeing it.
        unsafe { sys::fido_assert_free(&mut self.pointer) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_cancellation_maps_to_cancelled_status() {
        assert_eq!(Error::Cancelled.status(), Status::Cancelled);
    }

    #[test]
    fn accepts_selected_credential_in_allow_list() {
        let credential_ids = vec![b"first".to_vec(), b"second".to_vec()];

        assert!(validate_selected_credential_id(&credential_ids, b"second").is_ok());
    }

    #[test]
    fn rejects_empty_selected_credential_id() {
        assert!(validate_selected_credential_id(&[b"first".to_vec()], b"").is_err());
    }

    #[test]
    fn rejects_oversized_selected_credential_id() {
        let selected_credential_id = vec![0u8; MAX_CREDENTIAL_ID_SIZE + 1];
        let credential_ids = vec![selected_credential_id.clone()];

        assert!(validate_selected_credential_id(&credential_ids, &selected_credential_id).is_err());
    }

    #[test]
    fn rejects_selected_credential_id_absent_from_allow_list() {
        assert!(validate_selected_credential_id(&[b"first".to_vec()], b"second").is_err());
    }
}
