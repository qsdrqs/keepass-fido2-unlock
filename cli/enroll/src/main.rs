//! Command-line interface for creating and updating KeePassXC FIDO2 unlock files.
//!
//! Interactive secrets are obtained from the controlling terminal, while the
//! library owns credential verification, canonical serialization, and publication.

use keepass_fido2_enroll::{
    Broker, LockedFido2UnlockFileUpdate, PayloadPolicy, ProcessBroker, Result,
    VERIFICATION_INSTRUCTION, create_unlock_file, display_label, enroll_new, hex, load_key_file,
    parse_hex_slot, password_key, read_unlock_file, remove_wrapper,
};
use std::{
    env, fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process,
};
use zeroize::{Zeroize, Zeroizing};

const HELP: &str = r#"keepass-fido2-enroll - manage KeePassXC FIDO2 unlock files

USAGE
  keepass-fido2-enroll create <fido2-unlock-file> <label>
  keepass-fido2-enroll create-with-key-file <fido2-unlock-file> <label>
  keepass-fido2-enroll append <fido2-unlock-file> <label>
  keepass-fido2-enroll list <fido2-unlock-file>
  keepass-fido2-enroll remove <fido2-unlock-file> <slot-id>

COMMANDS
  create                Create a file containing the password component.
  create-with-key-file  Create a file containing password and key-file components.
  append                Enroll another authenticator; inherit the existing policy.
  list                  List enrolled slot IDs and labels.
  remove                Remove a slot ID; the final slot cannot be removed.

ARGUMENTS
  <fido2-unlock-file>  Binary FIDO2 unlock file, separate from the KDBX database.
  <label>              Human-readable authenticator description; need not be unique.
  <slot-id>            Stable 32-character ID printed by list and used by remove.

REQUIREMENTS
  Connect exactly one FIDO2 authenticator with a configured PIN and support for
  hmac-secret and credProtect.

EXAMPLES
  keepass-fido2-enroll create ~/Documents/personal.fido2 "primary-yubikey"
  keepass-fido2-enroll create-with-key-file ~/Documents/work.fido2 "office-key"
  keepass-fido2-enroll append ~/Documents/personal.fido2 "backup-key"
  keepass-fido2-enroll list ~/Documents/personal.fido2
  keepass-fido2-enroll remove ~/Documents/personal.fido2 0123456789abcdef0123456789abcdef

AFTER ENROLLMENT
  Open the KDBX in the modified KeePassXC, click "Use FIDO2 to unlock", select
  the FIDO2 unlock file, enter the PIN, click Unlock, and touch the authenticator.
  Enrollment does not read the KDBX, so verify the FIDO2 unlock file immediately.
"#;

const INVALID_INVOCATION: &str =
    "invalid command or arguments; run 'keepass-fido2-enroll --help' for usage";

fn help_requested(arguments: &[String]) -> bool {
    arguments.is_empty()
        || matches!(arguments, [argument] if argument == "-h" || argument == "--help")
}

fn write_help(output: &mut impl Write) -> io::Result<()> {
    output.write_all(HELP.as_bytes())
}

/// Reads a non-echoed secret from the controlling terminal into zeroizing storage.
fn prompt(prompt: &str) -> Result<Zeroizing<Vec<u8>>> {
    rpassword::prompt_password(prompt)
        .map(|value| Zeroizing::new(value.into_bytes()))
        .map_err(|e| format!("could not read terminal input: {e}"))
}

/// Reads an echoed line from the controlling terminal rather than standard input.
fn prompt_line(prompt: &str) -> Result<Zeroizing<String>> {
    let mut terminal = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| format!("could not open controlling terminal: {e}"))?;
    terminal
        .write_all(prompt.as_bytes())
        .map_err(|e| format!("could not write terminal prompt: {e}"))?;
    terminal
        .flush()
        .map_err(|e| format!("could not write terminal prompt: {e}"))?;

    read_terminal_line(&mut terminal)
}

/// Consumes one terminal line, strips CRLF, and retains the text in zeroizing storage.
fn read_terminal_line(reader: &mut impl Read) -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new(Vec::new());
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => return Err("terminal input ended before a complete line".into()),
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => bytes.push(byte[0]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(format!("could not read terminal input: {error}")),
        }
    }
    if bytes.ends_with(b"\r") {
        bytes.pop();
    }
    String::from_utf8(std::mem::take(&mut *bytes))
        .map(Zeroizing::new)
        .map_err(|_| "terminal input is not valid UTF-8".into())
}

/// Writes the post-publication verification reminder, falling back to stderr.
fn write_verification_instruction(primary: &mut impl Write, fallback: &mut impl Write) {
    if writeln!(primary, "{VERIFICATION_INSTRUCTION}").is_err() {
        let _ = writeln!(fallback, "{VERIFICATION_INSTRUCTION}");
    }
}

fn emit_verification_instruction() {
    let stdout = io::stdout();
    let stderr = io::stderr();
    write_verification_instruction(&mut stdout.lock(), &mut stderr.lock());
}

/// Runs one create or append enrollment transaction.
fn enrollment(path: PathBuf, label: String, create_policy: Option<PayloadPolicy>) -> Result<()> {
    let mut update = None;
    let policy = if let Some(policy) = create_policy {
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                return Err(
                    "FIDO2 unlock file already exists; use append or delete it explicitly".into(),
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!("could not inspect FIDO2 unlock file path: {error}"));
            }
        }
        policy
    } else {
        let locked = LockedFido2UnlockFileUpdate::open(&path)?;
        let policy = locked.unlock_file().payload_policy;
        update = Some(locked);
        policy
    };
    let mut broker = ProcessBroker;
    broker.probe()?;

    // Passwords, the optional key-file path, and the PIN are accepted only from
    // terminal-backed helpers; redirected standard input never supplies them.
    let mut password = prompt("Database password: ")?;
    let mut confirmation = prompt("Confirm database password: ")?;
    let passwords_match = password == confirmation;
    confirmation.zeroize();
    if !passwords_match {
        password.zeroize();
        return Err("database passwords did not match".into());
    }

    // KeePassXC derives PasswordKey as SHA-256(password). FileKey follows its
    // key-file compatibility rules, or is all zeroes for password-only payloads.
    let password_key = password_key(&mut password)?;
    let file_key = if policy == PayloadPolicy::PasswordAndKeyFile {
        let key_file_path = prompt_line("Key file path: ")?;
        if key_file_path.is_empty() {
            return Err("key file path is empty".into());
        }
        load_key_file(Path::new(key_file_path.as_str()))?
    } else {
        Zeroizing::new([0; 32])
    };
    let mut pin = prompt("FIDO PIN: ")?;
    let existing = update.as_ref().map(|locked| locked.unlock_file().clone());
    let unlock_file_result = enroll_new(
        existing,
        policy,
        label,
        &password_key,
        &file_key,
        &mut pin,
        &mut broker,
    );
    pin.zeroize();
    let unlock_file = unlock_file_result?;
    let result = if let Some(mut locked) = update {
        locked.set_unlock_file(unlock_file);
        locked.commit()
    } else {
        create_unlock_file(&path, &unlock_file)
    };
    result?;
    emit_verification_instruction();
    Ok(())
}

fn run() -> Result<()> {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if help_requested(&arguments) {
        let stdout = io::stdout();
        write_help(&mut stdout.lock()).map_err(|e| format!("could not write help: {e}"))?;
        return Ok(());
    }
    if arguments.len() < 2 || arguments.len() > 3 {
        return Err(INVALID_INVOCATION.into());
    }
    match arguments[0].as_str() {
        "create" if arguments.len() == 3 => enrollment(
            PathBuf::from(&arguments[1]),
            arguments[2].clone(),
            Some(PayloadPolicy::PasswordOnly),
        ),
        "create-with-key-file" if arguments.len() == 3 => enrollment(
            PathBuf::from(&arguments[1]),
            arguments[2].clone(),
            Some(PayloadPolicy::PasswordAndKeyFile),
        ),
        "append" if arguments.len() == 3 => {
            enrollment(PathBuf::from(&arguments[1]), arguments[2].clone(), None)
        }
        "list" if arguments.len() == 2 => {
            for wrapper in read_unlock_file(&PathBuf::from(&arguments[1]))?.wrappers {
                println!(
                    "{}\t{}",
                    hex(&wrapper.slot_id),
                    display_label(&wrapper.label)
                );
            }
            Ok(())
        }
        "remove" if arguments.len() == 3 => {
            let path = PathBuf::from(&arguments[1]);
            let mut locked = LockedFido2UnlockFileUpdate::open(&path)?;
            remove_wrapper(locked.unlock_file_mut(), parse_hex_slot(&arguments[2])?)?;
            locked.commit()
        }
        _ => Err(INVALID_INVOCATION.into()),
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("simulated output failure"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("simulated output failure"))
        }
    }

    #[test]
    fn verification_instruction_output_is_best_effort() {
        let mut primary = Vec::new();
        let mut fallback = Vec::new();
        write_verification_instruction(&mut primary, &mut fallback);
        assert_eq!(primary, format!("{VERIFICATION_INSTRUCTION}\n").as_bytes());
        assert!(fallback.is_empty());

        let mut fallback = Vec::new();
        write_verification_instruction(&mut FailingWriter, &mut fallback);
        assert_eq!(fallback, format!("{VERIFICATION_INSTRUCTION}\n").as_bytes());

        write_verification_instruction(&mut FailingWriter, &mut FailingWriter);
    }

    #[test]
    fn terminal_line_stops_at_newline() {
        let mut input = std::io::Cursor::new(b"/tmp/key file.keyx\r\nignored".to_vec());
        assert_eq!(
            read_terminal_line(&mut input).unwrap().as_str(),
            "/tmp/key file.keyx"
        );

        let mut incomplete = std::io::Cursor::new(b"incomplete".to_vec());
        assert!(read_terminal_line(&mut incomplete).is_err());
    }

    #[test]
    fn top_level_help_requests_are_recognized() {
        assert!(help_requested(&[]));
        assert!(help_requested(&["-h".into()]));
        assert!(help_requested(&["--help".into()]));
        assert!(!help_requested(&["list".into()]));
        assert!(!help_requested(&["list".into(), "--help".into()]));
    }
}
