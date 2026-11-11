//! Credentials live in the desktop keyring (KDE Wallet / Secret Service), never in files.
//!
//! These calls talk to the keyring over D-Bus and block; call them from the CLI or from
//! `spawn_blocking`, not directly on the async runtime.

use zeroize::Zeroizing;

use crate::config::APP;
use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Secret {
    /// Gmail app password.
    Password,
    /// Microsoft OAuth refresh token.
    RefreshToken,
}

impl Secret {
    const ALL: [Self; 2] = [Self::Password, Self::RefreshToken];

    const fn key(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::RefreshToken => "refresh_token",
        }
    }
}

fn entry(account: &str, secret: Secret) -> Result<keyring::Entry> {
    keyring::Entry::new(APP, &format!("{account}:{}", secret.key())).map_err(keyring_error)
}

fn keyring_error(e: keyring::Error) -> Error {
    Error::Keyring(format!(
        "{e}. The desktop keyring (KDE Wallet) must be running and unlocked."
    ))
}

pub fn get(account: &str, secret: Secret) -> Result<Option<Zeroizing<String>>> {
    match entry(account, secret)?.get_password() {
        Ok(value) => Ok(Some(Zeroizing::new(value))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(keyring_error(e)),
    }
}

pub fn set(account: &str, secret: Secret, value: &str) -> Result<()> {
    entry(account, secret)?
        .set_password(value)
        .map_err(keyring_error)
}

/// Remove every secret stored for an account. Missing entries are fine.
pub fn delete_all(account: &str) -> Result<()> {
    for secret in Secret::ALL {
        match entry(account, secret)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => {}
            Err(e) => return Err(keyring_error(e)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Live round trip through the desktop keyring. Creates and then deletes one entry
    /// named for the purpose. Run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "writes to and deletes from the real desktop keyring"]
    fn keyring_round_trip() {
        let account = "selftest-delete-me";
        delete_all(account).expect("clean start");
        assert!(get(account, Secret::RefreshToken).expect("get").is_none());
        set(account, Secret::RefreshToken, "first").expect("set");
        set(account, Secret::RefreshToken, "second").expect("overwrite");
        assert_eq!(
            get(account, Secret::RefreshToken)
                .expect("get")
                .as_deref()
                .map(String::as_str),
            Some("second")
        );
        delete_all(account).expect("delete");
        assert!(get(account, Secret::RefreshToken).expect("get").is_none());
    }
}
