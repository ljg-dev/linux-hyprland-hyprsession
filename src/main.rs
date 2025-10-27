use std::fs::create_dir_all;
use std::process::{exit, Command};
use std::{env, thread, time};

use clap::{Parser, ValueEnum};
use rpassword::prompt_password;
use zeroize::Zeroizing;

mod session;
use crate::session::{load_session, save_session, SessionAuthenticator, SessionError};

#[derive(Copy, Clone, Parser, PartialEq, ValueEnum)]
enum Mode {
    /// Load session then periodicly save session (default)
    Default,

    /// Periodicly save the session
    SaveOnly,

    /// Save the session once then exit
    SaveAndExit,

    /// Load the session then exit
    LoadAndExit,
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Args {
    /// Which mode to run the program in
    #[arg(short, long)]
    mode: Option<Mode>,

    /// Whether to ignore multiple clients with the same PID
    #[arg(long, default_value_t = true)]
    skip_duplicate_pids: bool,

    /// Interval between saving sessions (default: 60)
    #[arg(short = 'i', long)]
    save_interval: Option<u64>,

    /// The path where the session is saved (default: ~/.local/share)
    #[arg(short = 's', long)]
    session_path: Option<String>,

    /// Only simulate calls to Hyprland (supresses loading of session)
    #[arg(long, default_value_t = false)]
    simulate: bool,
}

fn main() {
    let args = Args::parse();
    let mode = args.mode.unwrap_or(Mode::Default);
    let save_interval = args.save_interval.unwrap_or(60);
    let simulate = args.simulate;
    let default_path = match env::var("HOME") {
        Ok(home) => home + "/.local/share/hyprsession",
        Err(_) => {
            eprintln!(
                "HOME environment variable not set; unable to determine default session path"
            );
            exit(1);
        }
    };
    let session_path = args.session_path.unwrap_or(default_path);

    if save_interval < 1 {
        eprintln!("Save interval needs to be a positive integer");
        exit(1);
    }

    if let Err(err) = create_dir_all(&session_path) {
        eprintln!(
            "Failed to create session directory {}: {}",
            session_path, err
        );
        exit(1);
    }

    let passphrase = match obtain_passphrase() {
        Ok(secret) => secret,
        Err(err) => {
            report_session_error("read passphrase", err);
            exit(1);
        }
    };

    let passphrase_ref: &str = passphrase.as_ref();
    let authenticator = match SessionAuthenticator::new(&session_path, passphrase_ref) {
        Ok(auth) => auth,
        Err(err) => {
            report_session_error("initialize authentication", err);
            exit(1);
        }
    };

    drop(passphrase);

    match mode {
        Mode::Default | Mode::LoadAndExit => {
            if let Err(err) = load_session(&session_path, simulate, &authenticator) {
                report_session_error("load session", err);
                if mode == Mode::LoadAndExit {
                    exit(1);
                }
            }
        }
        Mode::SaveAndExit | Mode::SaveOnly => {
            if let Err(err) = save_session(&session_path, args.skip_duplicate_pids, &authenticator)
            {
                report_session_error("save session", err);
                exit(1);
            }
        }
    }

    if mode == Mode::LoadAndExit || mode == Mode::SaveAndExit {
        exit(0);
    }

    loop {
        if let Err(err) = save_session(&session_path, args.skip_duplicate_pids, &authenticator) {
            report_session_error("save session", err);
        }
        thread::sleep(time::Duration::from_secs(save_interval));
    }
}

fn report_session_error(action: &str, error: SessionError) {
    eprintln!("Failed to {}: {}", action, error);
}

fn obtain_passphrase() -> Result<Zeroizing<String>, SessionError> {
    if let Ok(value) = env::var("HYPRSESSION_PASSPHRASE") {
        return Ok(Zeroizing::new(value));
    }

    if let Some(secret) = fetch_passphrase_from_keyring() {
        return Ok(secret);
    }

    prompt_password("Hyprsession passphrase: ")
        .map(Zeroizing::new)
        .map_err(SessionError::Io)
}

/// Attempts to read the passphrase from GNOME Keyring via `secret-tool`.
fn fetch_passphrase_from_keyring() -> Option<Zeroizing<String>> {
    let output = Command::new("secret-tool")
        .args(["lookup", "hyprsession", "passphrase"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let secret = String::from_utf8(output.stdout).ok()?;
    let secret = secret.trim_end_matches(|c| c == '\n' || c == '\r').to_owned();

    if secret.is_empty() {
        return None;
    }

    Some(Zeroizing::new(secret))
}
