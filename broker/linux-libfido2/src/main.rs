//! One-shot Linux broker entry point.
//!
//! The process reads exactly one framed request from stdin, writes exactly one
//! framed response to stdout, and exits. Stderr is intentionally unused so the
//! caller never has to merge diagnostic text with the binary protocol.

#![deny(clippy::undocumented_unsafe_blocks)]

mod fido;
mod protocol;

use std::io;
use std::process::ExitCode;

use protocol::{DecodeError, Request, Status};

fn main() -> ExitCode {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut output = stdout.lock();

    let request = match protocol::read_request(stdin.lock()) {
        Ok(request) => request,
        Err(error) => {
            // A version mismatch has a dedicated wire status. All other decode
            // failures share MalformedRequest, and no operation is trusted
            // enough to echo before the complete frame has been validated.
            let status = match error {
                DecodeError::UnsupportedVersion(_) => Status::UnsupportedVersion,
                _ => Status::MalformedRequest,
            };
            let _ = protocol::write_error(&mut output, None, status, &error.to_string());
            return ExitCode::FAILURE;
        }
    };

    let operation = request.operation();
    let result = match &request {
        Request::Create(request) => fido::create(request)
            .map(|response| protocol::write_create_response(&mut output, &response)),
        Request::Assert(request) => fido::assert(request)
            .map(|response| protocol::write_assert_response(&mut output, &response)),
        Request::Probe => fido::probe().map(|()| protocol::write_probe_response(&mut output)),
    };

    match result {
        // Success requires both the FIDO operation and its response write to
        // succeed. A write failure cannot be reported on the same output stream.
        Ok(Ok(())) => ExitCode::SUCCESS,
        Ok(Err(_)) => ExitCode::FAILURE,
        Err(error) => {
            let _ = protocol::write_error(
                &mut output,
                Some(operation),
                error.status(),
                &error.to_string(),
            );
            ExitCode::FAILURE
        }
    }
}
