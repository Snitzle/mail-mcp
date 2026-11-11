//! Settings, split by who is allowed to change them.
//!
//! * The **user config** (`~/.config/mail-mcp/config.toml`) lists accounts and cosmetic
//!   preferences. Anything running as the user can edit it, including an AI agent with a
//!   shell, so nothing in it can make the server less safe. It can only switch the server
//!   to read-only.
//! * The **policy** (`/etc/mail-mcp/policy.toml`) holds the settings that could weaken
//!   safety: send limits and which folders attachments may be read from. It is only
//!   honoured if root owns it and nobody else can write it. Without it, built-in defaults
//!   apply.
//!
//! The policy can also pin the account list: once pinned, an account that has been added
//! to, or altered in, the user config stops the server from starting. That closes the one
//! way an edited user config could matter: pointing an account name at a different mailbox.
//!
//! There is deliberately no setting that turns approval prompts off.
//!
//! Everything is read once at start-up and never again while the server runs.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, IoContext, Result};
use crate::fsutil;

pub const APP: &str = "mail-mcp";
pub const POLICY_FILE: &str = "/etc/mail-mcp/policy.toml";

const DEFAULT_PER_MINUTE: u32 = 10;
const DEFAULT_PER_DAY: u32 = 100;
const DEFAULT_ATTACH_DIRS: &[&str] = &["~/Documents", "~/Downloads", "~/Desktop", "~/Pictures"];
const MAX_CONFIG_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    Outlook,
    Gmail,
}

/// How the SMTP connection is secured.
#[cfg_attr(test, allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmtpSecurity {
    /// TLS from the first byte (port 465).
    Implicit,
    /// Plain connection upgraded with STARTTLS before anything else is sent (port 587).
    StartTls,
}

impl Provider {
    /// Server endpoints are compiled in. They are not configurable, so no config edit can
    /// point the server (and the user's credentials) at another host.
    pub const fn imap(self) -> (&'static str, u16) {
        match self {
            Self::Outlook => ("outlook.office365.com", 993),
            Self::Gmail => ("imap.gmail.com", 993),
        }
    }

    #[cfg_attr(test, allow(dead_code))]
    pub const fn smtp(self) -> (&'static str, u16, SmtpSecurity) {
        match self {
            Self::Outlook => ("smtp-mail.outlook.com", 587, SmtpSecurity::StartTls),
            Self::Gmail => ("smtp.gmail.com", 465, SmtpSecurity::Implicit),
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Outlook => "outlook",
            Self::Gmail => "gmail",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    /// Short handle used in tool calls, e.g. `hotmail`.
    pub name: String,
    pub address: String,
    pub provider: Provider,
    /// Microsoft Entra application (client) ID. Outlook only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// Other addresses that deliver to this mailbox (left out of reply-all).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    /// Save a copy to Sent after sending. Outlook and Gmail already do this themselves.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub save_sent_copy: bool,
}

impl Account {
    pub fn validate(&self) -> Result<()> {
        validate_account_name(&self.name)?;
        validate_address(&self.address)?;
        for alias in &self.aliases {
            validate_address(alias)?;
        }
        match (self.provider, &self.client_id) {
            (Provider::Outlook, None) => {
                return Err(Error::config(format!(
                    "account '{}' is an Outlook account and needs a client_id",
                    self.name
                )));
            }
            (_, Some(id)) => validate_client_id(id)?,
            (Provider::Gmail, None) => {}
        }
        if let Some(name) = &self.display_name
            && (name.chars().count() > 100 || name.chars().any(char::is_control))
        {
            return Err(Error::config(
                "display_name must be one line of at most 100 characters",
            ));
        }
        if let Some(signature) = &self.signature
            && signature.chars().count() > 2000
        {
            return Err(Error::config("signature must be at most 2000 characters"));
        }
        Ok(())
    }

    /// Every address that is "me" for this account, lower-cased.
    pub fn own_addresses(&self) -> Vec<String> {
        std::iter::once(&self.address)
            .chain(&self.aliases)
            .map(|a| a.to_lowercase())
            .collect()
    }

    pub fn domain(&self) -> &str {
        self.address.rsplit('@').next().unwrap_or_default()
    }
}

pub fn validate_account_name(name: &str) -> Result<()> {
    let ok = (1..=32).contains(&name.len())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        && !name.eq_ignore_ascii_case("all");
    if ok {
        Ok(())
    } else {
        Err(Error::config(format!(
            "account name '{name}' must be 1-32 letters, digits, dots, dashes or underscores (and not 'all')"
        )))
    }
}

/// A conservative check: one `@`, printable ASCII, no spaces or characters that have
/// meaning in a header or an SMTP command.
pub fn validate_address(address: &str) -> Result<()> {
    let bad = || Error::invalid(format!("'{address}' is not a usable email address"));
    let (local, domain) = address.rsplit_once('@').ok_or_else(bad)?;
    let plain = |c: char| {
        c.is_ascii_graphic()
            && !matches!(
                c,
                '<' | '>' | '(' | ')' | '[' | ']' | ',' | ';' | ':' | '"' | '\\' | '@'
            )
    };
    let ok = !local.is_empty()
        && local.len() <= 64
        && address.len() <= 254
        && local.chars().all(plain)
        && domain.contains('.')
        && !domain.starts_with(['.', '-'])
        && !domain.ends_with(['.', '-'])
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'));
    if ok { Ok(()) } else { Err(bad()) }
}

fn validate_client_id(id: &str) -> Result<()> {
    let ok = id.len() == 36
        && id.chars().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        });
    if ok {
        Ok(())
    } else {
        Err(Error::config(
            "client_id must look like xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (the Application (client) ID from Microsoft Entra)",
        ))
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserConfig {
    /// Turn every changing tool off. This can only make the server safer.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub read_only: bool,
    #[serde(default, rename = "account", skip_serializing_if = "Vec::is_empty")]
    pub accounts: Vec<Account>,
}

impl UserConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let text = match read_bounded(path) {
            Ok(text) => text,
            Err(Error::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(e) => return Err(e),
        };
        let config: Self =
            toml::from_str(&text).map_err(|e| Error::config(format!("{}: {e}", path.display())))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        for (i, account) in self.accounts.iter().enumerate() {
            account.validate()?;
            if self.accounts[..i]
                .iter()
                .any(|a| a.name.eq_ignore_ascii_case(&account.name))
            {
                return Err(Error::config(format!(
                    "account name '{}' is used twice",
                    account.name
                )));
            }
        }
        Ok(())
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let text = toml::to_string_pretty(self).map_err(|e| Error::config(e.to_string()))?;
        fsutil::write_private_atomic(path, text.as_bytes())
    }
}

fn read_bounded(path: &Path) -> Result<String> {
    let context = || format!("reading {}", path.display());
    let meta = fs::metadata(path).io_context(context())?;
    if meta.len() > MAX_CONFIG_BYTES {
        return Err(Error::config(format!(
            "{} is unreasonably large",
            path.display()
        )));
    }
    fs::read_to_string(path).io_context(context())
}

/// The safety-relevant settings, after defaults and validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub per_minute: u32,
    pub per_day: u32,
    /// Canonical paths of the folders attachments may be read from.
    pub attach_dirs: Vec<PathBuf>,
    pub read_only: bool,
    /// When not empty, the only accounts the server will run with.
    pub pinned_accounts: Vec<PinnedAccount>,
}

/// An account the policy allows, identified by everything that decides which mailbox it is.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedAccount {
    pub name: String,
    pub address: String,
    pub provider: Provider,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    per_minute: Option<u32>,
    per_day: Option<u32>,
    attach_dirs: Option<Vec<String>>,
    read_only: Option<bool>,
    #[serde(default, rename = "account")]
    accounts: Vec<PinnedAccount>,
}

impl Policy {
    /// Load the system policy, insisting that root owns it.
    pub fn load(home: &Path) -> Result<Self> {
        Self::load_from(Path::new(POLICY_FILE), 0, home)
    }

    /// `owner` is the uid that must own the file and its directory (root in production).
    fn load_from(path: &Path, owner: u32, home: &Path) -> Result<Self> {
        let file = match fs::symlink_metadata(path) {
            Ok(meta) => {
                let dir = path.parent().unwrap_or(Path::new("/"));
                let dir_meta =
                    fs::symlink_metadata(dir).io_context(format!("checking {}", dir.display()))?;
                check_trusted(path, &meta, owner, true)?;
                check_trusted(dir, &dir_meta, owner, false)?;
                let text = read_bounded(path)?;
                toml::from_str::<PolicyFile>(&text)
                    .map_err(|e| Error::config(format!("{}: {e}", path.display())))?
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => PolicyFile::default(),
            Err(e) => return Err(e).io_context(format!("checking {}", path.display())),
        };

        let per_minute = file.per_minute.unwrap_or(DEFAULT_PER_MINUTE);
        let per_day = file.per_day.unwrap_or(DEFAULT_PER_DAY);
        if per_minute == 0 || per_day == 0 || per_minute > 1_000 || per_day > 100_000 {
            return Err(Error::config(
                "policy send limits must be between 1 and 1000/minute, 100000/day",
            ));
        }
        let wanted: Vec<String> = file.attach_dirs.unwrap_or_else(|| {
            DEFAULT_ATTACH_DIRS
                .iter()
                .map(|d| (*d).to_owned())
                .collect()
        });
        let mut attach_dirs = Vec::new();
        for dir in wanted {
            let expanded = expand_home(&dir, home)?;
            // Folders that do not exist are simply not available.
            if let Ok(canonical) = fs::canonicalize(&expanded)
                && canonical.is_dir()
            {
                attach_dirs.push(canonical);
            }
        }
        Ok(Self {
            per_minute,
            per_day,
            attach_dirs,
            read_only: file.read_only.unwrap_or(false),
            pinned_accounts: file.accounts,
        })
    }

    /// If the policy pins accounts, every configured account must be one of them, with the
    /// same address and provider.
    pub fn check_accounts(&self, accounts: &[Account]) -> Result<()> {
        if self.pinned_accounts.is_empty() {
            return Ok(());
        }
        for account in accounts {
            let pinned = self.pinned_accounts.iter().any(|pin| {
                pin.name.eq_ignore_ascii_case(&account.name)
                    && pin.address.eq_ignore_ascii_case(&account.address)
                    && pin.provider == account.provider
            });
            if !pinned {
                return Err(Error::config(format!(
                    "account '{}' ({}) is not in the pinned account list in {POLICY_FILE}; refusing to start. If you added or changed this account yourself, add it to that file (as root).",
                    account.name, account.address
                )));
            }
        }
        Ok(())
    }
}

fn check_trusted(path: &Path, meta: &fs::Metadata, owner: u32, must_be_file: bool) -> Result<()> {
    let kind_ok = if must_be_file {
        meta.is_file()
    } else {
        meta.is_dir()
    };
    if !kind_ok {
        return Err(Error::config(format!(
            "{} must be a regular {} (not a link)",
            path.display(),
            if must_be_file { "file" } else { "directory" }
        )));
    }
    if meta.uid() != owner || meta.mode() & 0o022 != 0 {
        return Err(Error::config(format!(
            "{} must be owned by {} and not writable by anyone else; refusing to start. Fix with: sudo chown root:root {p} && sudo chmod go-w {p}",
            path.display(),
            if owner == 0 {
                "root".to_owned()
            } else {
                format!("uid {owner}")
            },
            p = path.display(),
        )));
    }
    Ok(())
}

fn expand_home(dir: &str, home: &Path) -> Result<PathBuf> {
    let path = match dir.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None if dir == "~" => home.to_path_buf(),
        None => PathBuf::from(dir),
    };
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(Error::config(format!(
            "attach_dirs entry '{dir}' must be an absolute path or start with ~/"
        )))
    }
}

/// Where our files live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    pub home: PathBuf,
    pub config_file: PathBuf,
    pub state_dir: PathBuf,
    /// Where `save_attachments` writes. Nothing is ever saved anywhere else.
    pub attachments_dir: PathBuf,
}

impl Paths {
    pub fn from_env() -> Result<Self> {
        let home = absolute_env("HOME")
            .ok_or_else(|| Error::config("HOME is not set to an absolute path"))?;
        let config_base = absolute_env("XDG_CONFIG_HOME").unwrap_or_else(|| home.join(".config"));
        let state_base =
            absolute_env("XDG_STATE_HOME").unwrap_or_else(|| home.join(".local/state"));
        Ok(Self {
            config_file: config_base.join(APP).join("config.toml"),
            state_dir: state_base.join(APP),
            attachments_dir: home.join("Downloads/mail-attachments"),
            home,
        })
    }

    pub fn audit_log(&self) -> PathBuf {
        self.state_dir.join("audit.log")
    }

    pub fn sends_file(&self) -> PathBuf {
        self.state_dir.join("sends.json")
    }
}

fn absolute_env(name: &str) -> Option<PathBuf> {
    let value = PathBuf::from(std::env::var_os(name)?);
    value.is_absolute().then_some(value)
}

/// Everything the server needs to know, fixed at start-up.
#[derive(Debug, Clone)]
pub struct Settings {
    pub accounts: Vec<Account>,
    pub read_only: bool,
    pub policy: Policy,
    pub paths: Paths,
}

impl Settings {
    pub fn load() -> Result<Self> {
        let paths = Paths::from_env()?;
        let user = UserConfig::load(&paths.config_file)?;
        let policy = Policy::load(&paths.home)?;
        policy.check_accounts(&user.accounts)?;
        let env_read_only = std::env::var("MAIL_MCP_READ_ONLY")
            .is_ok_and(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"));
        Ok(Self {
            read_only: user.read_only || policy.read_only || env_read_only,
            accounts: user.accounts,
            policy,
            paths,
        })
    }

    /// Find an account by its name or its address.
    pub fn account(&self, wanted: &str) -> Result<&Account> {
        self.accounts
            .iter()
            .find(|a| a.name.eq_ignore_ascii_case(wanted) || a.address.eq_ignore_ascii_case(wanted))
            .ok_or_else(|| {
                let names: Vec<&str> = self.accounts.iter().map(|a| a.name.as_str()).collect();
                Error::invalid(if names.is_empty() {
                    "No accounts are configured yet. The user must run `mail-mcp add-outlook` or `mail-mcp add-gmail` in a terminal.".to_owned()
                } else {
                    format!("Unknown account '{wanted}'. Configured accounts: {}", names.join(", "))
                })
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn outlook(name: &str) -> Account {
        Account {
            name: name.into(),
            address: "someone@example.com".into(),
            provider: Provider::Outlook,
            client_id: Some("01234567-89ab-cdef-0123-456789abcdef".into()),
            display_name: None,
            signature: None,
            aliases: vec![],
            save_sent_copy: false,
        }
    }

    fn me() -> u32 {
        rustix::process::getuid().as_raw()
    }

    #[test]
    fn addresses_are_checked() {
        for good in [
            "a@b.co",
            "first.last+tag@sub.example.org",
            "x_y-z@mail.example.co.uk",
        ] {
            assert!(validate_address(good).is_ok(), "{good}");
        }
        for bad in [
            "",
            "nope",
            "a@b",
            "a b@c.de",
            "a@b .de",
            "a@-b.de",
            "a@b.de.",
            "<a@b.de>",
            "a@b.de\r\nBcc: x@y.z",
            "a,b@c.de",
            "\"a\"@b.de",
            "a@b.de>",
            "ü@b.de",
            "a@@b.de",
        ] {
            assert!(validate_address(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn account_rules() {
        assert!(outlook("hotmail").validate().is_ok());
        assert!(outlook("all").validate().is_err());
        assert!(outlook("has space").validate().is_err());
        let mut no_id = outlook("h");
        no_id.client_id = None;
        assert!(no_id.validate().is_err());
        let mut bad_id = outlook("h");
        bad_id.client_id = Some("not-a-guid".into());
        assert!(bad_id.validate().is_err());
    }

    #[test]
    fn user_config_round_trips_and_rejects_unknown_keys() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        let config = UserConfig {
            read_only: false,
            accounts: vec![outlook("hotmail")],
        };
        config.save(&path).expect("save");
        assert_eq!(UserConfig::load(&path).expect("load"), config);

        // A key that used to switch approvals off in the old Python server must be an error,
        // not silently accepted.
        fs::write(&path, "confirm_mode = \"none\"\n").expect("write");
        assert!(UserConfig::load(&path).is_err());
    }

    #[test]
    fn missing_user_config_is_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            UserConfig::load(&dir.path().join("none.toml")).expect("load"),
            UserConfig::default()
        );
    }

    #[test]
    fn duplicate_account_names_are_rejected() {
        let config = UserConfig {
            read_only: false,
            accounts: vec![outlook("a"), outlook("A")],
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn missing_policy_gives_defaults() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path().join("home");
        fs::create_dir_all(home.join("Documents")).expect("mkdir");
        let policy =
            Policy::load_from(&dir.path().join("etc/policy.toml"), me(), &home).expect("load");
        assert_eq!((policy.per_minute, policy.per_day), (10, 100));
        assert_eq!(
            policy.attach_dirs,
            [fs::canonicalize(home.join("Documents")).expect("canon")]
        );
        assert!(!policy.read_only);
    }

    #[test]
    fn policy_is_read_when_owned_and_not_writable_by_others() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).expect("chmod dir");
        let path = dir.path().join("policy.toml");
        fs::write(
            &path,
            "per_minute = 2\nper_day = 5\nattach_dirs = []\nread_only = true\n",
        )
        .expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        let policy = Policy::load_from(&path, me(), dir.path()).expect("load");
        assert_eq!(
            (policy.per_minute, policy.per_day, policy.read_only),
            (2, 5, true)
        );
        assert!(policy.attach_dirs.is_empty());
    }

    #[test]
    fn policy_with_wrong_owner_or_mode_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).expect("chmod dir");
        let path = dir.path().join("policy.toml");
        fs::write(&path, "per_minute = 500\n").expect("write");

        // Wrong owner: the file is ours, but root (uid 0) is required.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        if me() != 0 {
            assert!(Policy::load_from(&path, 0, dir.path()).is_err());
        }
        // Writable by group/others.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).expect("chmod");
        assert!(Policy::load_from(&path, me(), dir.path()).is_err());
        // Directory writable by others (file could be swapped).
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o777)).expect("chmod dir");
        assert!(Policy::load_from(&path, me(), dir.path()).is_err());
    }

    #[test]
    fn pinned_accounts_reject_additions_and_changes() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).expect("chmod dir");
        let path = dir.path().join("policy.toml");
        fs::write(
            &path,
            "[[account]]\nname = \"hotmail\"\naddress = \"someone@example.com\"\nprovider = \"outlook\"\n",
        )
        .expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
        let policy = Policy::load_from(&path, me(), dir.path()).expect("load");

        assert!(policy.check_accounts(&[outlook("hotmail")]).is_ok());
        assert!(policy.check_accounts(&[]).is_ok());
        // An extra account.
        assert!(
            policy
                .check_accounts(&[outlook("hotmail"), outlook("extra")])
                .is_err()
        );
        // The same name pointed at another mailbox.
        let mut redirected = outlook("hotmail");
        redirected.address = "attacker@example.com".into();
        assert!(policy.check_accounts(&[redirected]).is_err());
    }

    #[test]
    fn without_pins_any_account_is_accepted() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy =
            Policy::load_from(&dir.path().join("none.toml"), me(), dir.path()).expect("load");
        assert!(policy.check_accounts(&[outlook("anything")]).is_ok());
    }

    #[test]
    fn policy_symlink_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).expect("chmod dir");
        let real = dir.path().join("real.toml");
        fs::write(&real, "per_minute = 500\n").expect("write");
        let link = dir.path().join("policy.toml");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        assert!(Policy::load_from(&link, me(), dir.path()).is_err());
    }

    #[test]
    fn policy_rejects_unknown_keys_and_silly_limits() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).expect("chmod dir");
        let path = dir.path().join("policy.toml");
        for body in [
            "confirm = false\n",
            "per_minute = 0\n",
            "attach_dirs = [\"relative/path\"]\n",
        ] {
            fs::write(&path, body).expect("write");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("chmod");
            assert!(
                Policy::load_from(&path, me(), dir.path()).is_err(),
                "{body}"
            );
        }
    }
}
