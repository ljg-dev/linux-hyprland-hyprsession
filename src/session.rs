use std::collections::HashSet;
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use argon2::Argon2;
use hex::{decode as hex_decode, encode as hex_encode};
use hmac::{Hmac, Mac};
use hyprland::data::{Client, Clients};
use hyprland::dispatch::*;
use hyprland::prelude::*;
use hyprland::shared::HyprError;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

const EXEC_FILE_NAME: &str = "exec.json";
const SIGNATURE_FILE_NAME: &str = "exec.json.sig";
const SALT_FILE_NAME: &str = "key.salt";
const SESSION_FORMAT_VERSION: u32 = 1;
const SIGNATURE_FORMAT_VERSION: u32 = 1;
const HMAC_KEY_LENGTH: usize = 32;
const SALT_LENGTH: usize = 16;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
pub enum SessionError {
    Io(io::Error),
    Hyprland(HyprError),
    Serde(serde_json::Error),
    KeyDerivation(String),
    Crypto(String),
    SignatureMissing,
    InvalidData(String),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionError::Io(err) => write!(f, "I/O error: {}", err),
            SessionError::Hyprland(err) => write!(f, "Hyprland dispatch error: {}", err),
            SessionError::Serde(err) => write!(f, "Failed to parse session file: {}", err),
            SessionError::KeyDerivation(msg) => write!(f, "Key derivation failed: {}", msg),
            SessionError::Crypto(msg) => write!(f, "Cryptographic error: {}", msg),
            SessionError::SignatureMissing => write!(f, "Session signature is missing"),
            SessionError::InvalidData(msg) => write!(f, "{}", msg),
        }
    }
}

impl Error for SessionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            SessionError::Io(err) => Some(err),
            SessionError::Hyprland(err) => Some(err),
            SessionError::Serde(err) => Some(err),
            SessionError::KeyDerivation(_) => None,
            SessionError::Crypto(_) => None,
            SessionError::SignatureMissing => None,
            SessionError::InvalidData(_) => None,
        }
    }
}

impl From<io::Error> for SessionError {
    fn from(err: io::Error) -> Self {
        SessionError::Io(err)
    }
}

impl From<HyprError> for SessionError {
    fn from(err: HyprError) -> Self {
        SessionError::Hyprland(err)
    }
}

impl From<serde_json::Error> for SessionError {
    fn from(err: serde_json::Error) -> Self {
        SessionError::Serde(err)
    }
}

pub type SessionResult<T> = Result<T, SessionError>;

pub struct SessionAuthenticator {
    key: [u8; HMAC_KEY_LENGTH],
}

impl SessionAuthenticator {
    pub fn new(base_path: &str, passphrase: &str) -> SessionResult<Self> {
        let base_dir = Path::new(base_path);
        ensure_secure_dir(base_dir)?;
        let salt = load_or_create_salt(base_dir)?;
        let mut key = [0u8; HMAC_KEY_LENGTH];
        Argon2::default()
            .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
            .map_err(|err| SessionError::KeyDerivation(err.to_string()))?;

        Ok(SessionAuthenticator { key })
    }

    pub fn sign(&self, data: &[u8]) -> SessionResult<Vec<u8>> {
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .map_err(|err| SessionError::Crypto(err.to_string()))?;
        mac.update(data);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    pub fn verify(&self, data: &[u8], expected_mac: &[u8]) -> SessionResult<()> {
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .map_err(|err| SessionError::Crypto(err.to_string()))?;
        mac.update(data);
        mac.verify_slice(expected_mac)
            .map_err(|_| SessionError::InvalidData("Session signature mismatch".to_string()))
    }
}

impl Drop for SessionAuthenticator {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionCommand {
    argv: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionEntry {
    properties: Vec<String>,
    command: SessionCommand,
}

#[derive(Debug, Serialize, Deserialize)]
struct SessionFile {
    version: u32,
    entries: Vec<SessionEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SignatureFile {
    version: u32,
    mac_hex: String,
}

pub fn save_session(
    base_path: &str,
    skip_duplicate_pids: bool,
    authenticator: &SessionAuthenticator,
) -> SessionResult<()> {
    let base_dir = Path::new(base_path);
    ensure_secure_dir(base_dir)?;
    let session_path = base_dir.join(EXEC_FILE_NAME);
    let signature_path = base_dir.join(SIGNATURE_FILE_NAME);

    let clients = Clients::get()?;
    let mut seen_pids = HashSet::new();
    let mut entries = Vec::new();

    for client in clients.iter() {
        if skip_duplicate_pids && !seen_pids.insert(client.pid) {
            continue;
        }

        match fetch_command(client) {
            Ok(command) => {
                let properties = collect_properties(client);
                entries.push(SessionEntry {
                    properties,
                    command,
                });
            }
            Err(err) => {
                eprintln!(
                    "Skipping client with PID {} due to error: {}",
                    client.pid, err
                );
            }
        }
    }

    let session = SessionFile {
        version: SESSION_FORMAT_VERSION,
        entries,
    };

    let session_bytes = serialize_session(&session)?;
    let mac = authenticator.sign(&session_bytes)?;

    write_bytes_atomic(&session_path, &session_bytes, Some(0o600))?;
    write_signature_file(&signature_path, &mac)?;

    println!("Session saved");
    Ok(())
}

pub fn load_session(
    base_path: &str,
    simulate: bool,
    authenticator: &SessionAuthenticator,
) -> SessionResult<()> {
    let base_dir = Path::new(base_path);
    ensure_secure_dir(base_dir)?;
    let session_path = base_dir.join(EXEC_FILE_NAME);
    let signature_path = base_dir.join(SIGNATURE_FILE_NAME);

    if !session_path.exists() {
        return Ok(());
    }

    ensure_regular_file(&session_path)?;
    if !signature_path.exists() {
        return Err(SessionError::SignatureMissing);
    }
    ensure_regular_file(&signature_path)?;

    let session_bytes = fs::read(&session_path)?;
    let signature = read_signature_file(&signature_path)?;
    if signature.version != SIGNATURE_FORMAT_VERSION {
        return Err(SessionError::InvalidData(format!(
            "Unsupported signature file version {}",
            signature.version
        )));
    }

    let expected_mac = hex_decode(signature.mac_hex.as_str()).map_err(|err| {
        SessionError::InvalidData(format!("Invalid session signature encoding: {}", err))
    })?;
    authenticator.verify(&session_bytes, &expected_mac)?;

    let session: SessionFile = serde_json::from_slice(&session_bytes)?;

    if session.version != SESSION_FORMAT_VERSION {
        return Err(SessionError::InvalidData(format!(
            "Unsupported session file version {}",
            session.version
        )));
    }

    for entry in session.entries {
        validate_command(&entry.command)?;
        let command_str = render_command(&entry.command)?;
        let options = format!("[{}]", entry.properties.join(";"));
        let payload = format!("{} {}", options, command_str);

        if !simulate {
            hyprland::dispatch!(Exec, &payload)?;
        }
        println!("Dispatch exec {}", payload);
    }

    Ok(())
}

fn collect_properties(client: &Client) -> Vec<String> {
    let mut props = Vec::new();
    props.push(format!("monitor {}", client.monitor));
    props.push(format!("workspace {} silent", client.workspace.id));

    if client.floating {
        props.push("float".to_string());
    }

    props.push(format!("move {} {}", client.at.0, client.at.1));
    props.push(format!("size {} {}", client.size.0, client.size.1));

    if client.pinned {
        props.push("pin".to_string());
    }

    props.push(format!("fullscreenstate {}", client.fullscreen as i32));
    props
}

fn fetch_command(info: &Client) -> SessionResult<SessionCommand> {
    let pid = info.pid;
    let exe_path = PathBuf::from(format!("/proc/{}/exe", pid));
    let exe = fs::read_link(&exe_path).map_err(|err| {
        SessionError::InvalidData(format!(
            "Unable to resolve executable for PID {}: {}",
            pid, err
        ))
    })?;

    let mut cmdline = Vec::new();
    let mut file = File::open(format!("/proc/{}/cmdline", pid)).map_err(|err| {
        SessionError::InvalidData(format!("Unable to read cmdline for PID {}: {}", pid, err))
    })?;
    file.read_to_end(&mut cmdline)?;

    if cmdline.is_empty() {
        return Err(SessionError::InvalidData(format!(
            "Process {} has an empty command line",
            pid
        )));
    }

    if let Some(0) = cmdline.last() {
        cmdline.pop();
    }

    let mut argv: Vec<String> = cmdline
        .split(|byte| *byte == 0)
        .map(|segment| String::from_utf8_lossy(segment).into_owned())
        .collect();

    if argv.is_empty() {
        return Err(SessionError::InvalidData(format!(
            "Process {} returned no arguments",
            pid
        )));
    }

    argv[0] = exe.to_string_lossy().into_owned();
    Ok(SessionCommand { argv })
}

fn render_command(command: &SessionCommand) -> SessionResult<String> {
    if command.argv.is_empty() {
        return Err(SessionError::InvalidData(
            "Command recorded without arguments".to_string(),
        ));
    }

    let escaped_parts: Vec<String> = command.argv.iter().map(|arg| shell_escape(arg)).collect();
    Ok(escaped_parts.join(" "))
}

fn shell_escape(segment: &str) -> String {
    if segment.is_empty() {
        return "''".to_string();
    }

    let mut escaped = String::with_capacity(segment.len() + 2);
    escaped.push('\'');
    for ch in segment.chars() {
        if ch == '\'' {
            escaped.push_str("'\\''");
        } else {
            escaped.push(ch);
        }
    }
    escaped.push('\'');
    escaped
}

fn validate_command(command: &SessionCommand) -> SessionResult<()> {
    if command.argv.is_empty() {
        return Err(SessionError::InvalidData(
            "Command recorded without arguments".to_string(),
        ));
    }

    let executable = Path::new(&command.argv[0]);
    if !executable.is_absolute() {
        return Err(SessionError::InvalidData(format!(
            "Executable path {} is not absolute",
            executable.display()
        )));
    }

    let metadata = fs::metadata(executable).map_err(|err| {
        SessionError::InvalidData(format!(
            "Unable to validate executable {}: {}",
            executable.display(),
            err
        ))
    })?;

    if !metadata.file_type().is_file() {
        return Err(SessionError::InvalidData(format!(
            "Executable path {} is not a regular file",
            executable.display()
        )));
    }

    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode();
        if mode & 0o111 == 0 {
            return Err(SessionError::InvalidData(format!(
                "Executable {} does not have execute permissions",
                executable.display()
            )));
        }

        if mode & 0o002 != 0 {
            return Err(SessionError::InvalidData(format!(
                "Executable {} is world-writable, refusing to execute",
                executable.display()
            )));
        }
    }

    Ok(())
}

fn ensure_secure_dir(base_dir: &Path) -> SessionResult<()> {
    let metadata = fs::symlink_metadata(base_dir)?;
    if metadata.file_type().is_symlink() {
        return Err(SessionError::InvalidData(format!(
            "Session directory {} must not be a symlink",
            base_dir.display()
        )));
    }

    if !metadata.file_type().is_dir() {
        return Err(SessionError::InvalidData(format!(
            "Session path {} is not a directory",
            base_dir.display()
        )));
    }

    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            fs::set_permissions(base_dir, fs::Permissions::from_mode(0o700))?;
        }
    }

    Ok(())
}

fn ensure_regular_file(path: &Path) -> SessionResult<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(SessionError::InvalidData(format!(
            "Session file {} must not be a symlink",
            path.display()
        )));
    }

    if !metadata.file_type().is_file() {
        return Err(SessionError::InvalidData(format!(
            "Session file {} is not a regular file",
            path.display()
        )));
    }

    #[cfg(unix)]
    {
        let mode = metadata.permissions().mode();
        if mode & 0o177 != 0 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
    }

    Ok(())
}

fn serialize_session(session: &SessionFile) -> SessionResult<Vec<u8>> {
    let mut buffer = Vec::new();
    serde_json::to_writer_pretty(&mut buffer, session)?;
    Ok(buffer)
}

fn write_signature_file(path: &Path, mac: &[u8]) -> SessionResult<()> {
    let signature = SignatureFile {
        version: SIGNATURE_FORMAT_VERSION,
        mac_hex: hex_encode(mac),
    };
    let bytes = serde_json::to_vec_pretty(&signature)?;
    write_bytes_atomic(path, &bytes, Some(0o600))
}

fn read_signature_file(path: &Path) -> SessionResult<SignatureFile> {
    let bytes = fs::read(path)?;
    let signature: SignatureFile = serde_json::from_slice(&bytes)?;
    Ok(signature)
}

fn write_bytes_atomic(path: &Path, data: &[u8], mode: Option<u32>) -> SessionResult<()> {
    let parent = path.parent().ok_or_else(|| {
        SessionError::InvalidData(format!(
            "Cannot determine parent directory for {}",
            path.display()
        ))
    })?;

    let identifier = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("hyprsession.tmp");

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| SessionError::InvalidData(format!("System time error: {}", err)))?
        .as_nanos();
    let temp_name = parent.join(format!(".{}.{}.tmp", identifier, unique));

    let mut temp_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_name)?;

    temp_file.write_all(data)?;
    temp_file.sync_all()?;

    drop(temp_file);

    if let Err(err) = fs::rename(&temp_name, path) {
        let _ = fs::remove_file(&temp_name);
        return Err(SessionError::Io(err));
    }

    #[cfg(unix)]
    if let Some(mode) = mode {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }

    Ok(())
}

fn load_or_create_salt(base_dir: &Path) -> SessionResult<[u8; SALT_LENGTH]> {
    let salt_path = base_dir.join(SALT_FILE_NAME);

    if salt_path.exists() {
        ensure_regular_file(&salt_path)?;
        let bytes = fs::read(&salt_path)?;
        if bytes.len() != SALT_LENGTH {
            return Err(SessionError::InvalidData(format!(
                "Salt file {} has invalid length",
                salt_path.display()
            )));
        }
        let mut salt = [0u8; SALT_LENGTH];
        salt.copy_from_slice(&bytes);
        Ok(salt)
    } else {
        let mut salt = [0u8; SALT_LENGTH];
        OsRng.fill_bytes(&mut salt);
        write_bytes_atomic(&salt_path, &salt, Some(0o600))?;
        Ok(salt)
    }
}
