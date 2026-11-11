//! IMAP access.
//!
//! Everything that goes on the wire is built from typed values: message UIDs are numbers,
//! dates are dates, and free text (search terms, folder names, labels) passes through
//! [`quote`], which refuses control characters and escapes the rest. There is no path by
//! which a string from a tool call or from an email is spliced into a command unquoted.

use std::sync::Arc;
use std::time::Duration;

use async_imap::imap_proto::NameAttribute;
use async_imap::types::{Fetch, Flag};
use chrono::{DateTime, FixedOffset, NaiveDate};
use futures::TryStreamExt;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use zeroize::Zeroizing;

use crate::config::{Account, Provider};
use crate::error::{Error, Result};
use crate::mutf7;
use crate::oauth::xoauth2_payload;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(90);
/// How much of a message is fetched when it is too large to download whole.
pub const PARTIAL_BYTES: u32 = 2 * 1024 * 1024;
const PREVIEW_BYTES: u32 = 16 * 1024;
const MAX_QUOTED_CHARS: usize = 1000;
pub const MAX_UIDS_PER_CALL: usize = 500;

/// How to sign in.
pub enum Credentials {
    /// Gmail app password.
    Password(Zeroizing<String>),
    /// OAuth access token (Outlook).
    AccessToken(Zeroizing<String>),
}

/// A TLS client configuration that verifies the server's certificate chain and host name
/// against Mozilla's root set, and speaks TLS 1.2 or newer only.
pub fn tls_config() -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Network(format!("TLS setup: {e}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

async fn timed<T, E>(
    what: &'static str,
    limit: Duration,
    work: impl Future<Output = std::result::Result<T, E>>,
) -> Result<T>
where
    Error: From<E>,
{
    match tokio::time::timeout(limit, work).await {
        Ok(result) => result.map_err(Error::from),
        Err(_) => Err(Error::Timeout(what)),
    }
}

/// Quote a string for use as an IMAP quoted string.
pub fn quote(value: &str) -> Result<String> {
    if value.chars().any(char::is_control) {
        return Err(Error::invalid(
            "Line breaks and control characters are not allowed in search terms, labels or folder names",
        ));
    }
    if value.chars().count() > MAX_QUOTED_CHARS {
        return Err(Error::invalid("That value is too long"));
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        if c == '\\' || c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    Ok(out)
}

/// A mailbox name as it goes on the wire, before the IMAP library quotes it.
fn wire_name(name: &str) -> Result<String> {
    if name.is_empty() || name.chars().count() > 200 || name.chars().any(char::is_control) {
        return Err(Error::invalid(
            "Folder names must be 1-200 characters with no line breaks",
        ));
    }
    Ok(mutf7::encode(name))
}

/// A non-empty, de-duplicated, bounded set of message UIDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UidSet(Vec<u32>);

impl UidSet {
    pub fn new(uids: &[u32]) -> Result<Self> {
        let mut unique: Vec<u32> = Vec::with_capacity(uids.len());
        for uid in uids {
            if *uid == 0 {
                return Err(Error::invalid("uid 0 is not a valid message id"));
            }
            if !unique.contains(uid) {
                unique.push(*uid);
            }
        }
        if unique.is_empty() {
            return Err(Error::invalid("At least one uid is required"));
        }
        if unique.len() > MAX_UIDS_PER_CALL {
            return Err(Error::invalid(format!(
                "At most {MAX_UIDS_PER_CALL} emails per call"
            )));
        }
        Ok(Self(unique))
    }

    pub fn single(uid: u32) -> Result<Self> {
        Self::new(&[uid])
    }

    pub fn as_slice(&self) -> &[u32] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    fn contains(&self, uid: u32) -> bool {
        self.0.contains(&uid)
    }

    fn wire(&self) -> String {
        self.0
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// Folders with a standard role (RFC 6154 special-use).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Special {
    Drafts,
    Sent,
    Trash,
    Junk,
    All,
    Archive,
    Flagged,
}

impl Special {
    /// The friendly names a tool call may use for this folder.
    pub fn from_alias(alias: &str) -> Option<Self> {
        Some(match alias.to_ascii_lowercase().as_str() {
            "drafts" | "draft" => Self::Drafts,
            "sent" => Self::Sent,
            "trash" | "bin" | "deleted" => Self::Trash,
            "spam" | "junk" => Self::Junk,
            "all" => Self::All,
            "archive" => Self::Archive,
            "starred" | "flagged" => Self::Flagged,
            _ => return None,
        })
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Drafts => "drafts",
            Self::Sent => "sent",
            Self::Trash => "trash",
            Self::Junk => "spam",
            Self::All => "all",
            Self::Archive => "archive",
            Self::Flagged => "starred",
        }
    }

    /// Names to try when the server does not advertise special-use flags.
    const fn fallbacks(self, provider: Provider) -> &'static [&'static str] {
        match (provider, self) {
            (Provider::Gmail, Self::Drafts) => &["[Gmail]/Drafts"],
            (Provider::Gmail, Self::Sent) => &["[Gmail]/Sent Mail"],
            (Provider::Gmail, Self::Trash) => &["[Gmail]/Trash", "[Gmail]/Bin"],
            (Provider::Gmail, Self::Junk) => &["[Gmail]/Spam"],
            (Provider::Gmail, Self::All | Self::Archive) => &["[Gmail]/All Mail"],
            (Provider::Gmail, Self::Flagged) => &["[Gmail]/Starred"],
            (Provider::Outlook, Self::Drafts) => &["Drafts"],
            (Provider::Outlook, Self::Sent) => &["Sent", "Sent Items"],
            (Provider::Outlook, Self::Trash) => &["Deleted", "Deleted Items"],
            (Provider::Outlook, Self::Junk) => &["Junk", "Junk Email"],
            (Provider::Outlook, Self::Archive) => &["Archive"],
            (Provider::Outlook, Self::All | Self::Flagged) => &[],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folder {
    /// The folder name as people see it (decoded).
    pub name: String,
    pub special: Option<Special>,
    pub selectable: bool,
}

/// Search criteria. Every string is quoted when rendered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Term {
    Unseen,
    From(String),
    To(String),
    Subject(String),
    /// Anywhere in the headers or body.
    Text(String),
    Since(NaiveDate),
    Before(NaiveDate),
    /// A header field (fixed name) containing the given text.
    Header(&'static str, String),
    /// Gmail's own search syntax (`X-GM-RAW`).
    GmailRaw(String),
    Or(Box<Term>, Box<Term>),
}

impl Term {
    fn render(&self) -> Result<String> {
        const MONTHS: [&str; 12] = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
        ];
        let date = |d: &NaiveDate| {
            use chrono::Datelike;
            format!("{}-{}-{}", d.day(), MONTHS[d.month0() as usize], d.year())
        };
        Ok(match self {
            Self::Unseen => "UNSEEN".to_owned(),
            Self::From(v) => format!("FROM {}", quote(v)?),
            Self::To(v) => format!("TO {}", quote(v)?),
            Self::Subject(v) => format!("SUBJECT {}", quote(v)?),
            Self::Text(v) => format!("TEXT {}", quote(v)?),
            Self::Since(d) => format!("SINCE {}", date(d)),
            Self::Before(d) => format!("BEFORE {}", date(d)),
            Self::Header(name, v) => format!("HEADER {name} {}", quote(v)?),
            Self::GmailRaw(v) => format!("X-GM-RAW {}", quote(v)?),
            Self::Or(a, b) => format!("OR {} {}", a.render()?, b.render()?),
        })
    }
}

/// Render a whole search command argument (all terms must match).
pub fn render_search(terms: &[Term]) -> Result<String> {
    if terms.is_empty() {
        return Ok("ALL".to_owned());
    }
    let rendered = terms
        .iter()
        .map(Term::render)
        .collect::<Result<Vec<_>>>()?
        .join(" ");
    // Quoted strings may only carry non-ASCII text when a charset is declared.
    Ok(if rendered.is_ascii() {
        rendered
    } else {
        format!("CHARSET UTF-8 {rendered}")
    })
}

/// Flags we report and set.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Flags {
    pub seen: bool,
    pub flagged: bool,
    pub draft: bool,
}

impl Flags {
    fn of(fetch: &Fetch) -> Self {
        let mut flags = Self::default();
        for flag in fetch.flags() {
            match flag {
                Flag::Seen => flags.seen = true,
                Flag::Flagged => flags.flagged = true,
                Flag::Draft => flags.draft = true,
                _ => {}
            }
        }
        flags
    }
}

/// One row of a message listing.
#[derive(Debug, Clone)]
pub struct Summary {
    pub uid: u32,
    pub flags: Flags,
    /// Gmail labels (decoded); empty elsewhere.
    pub labels: Vec<String>,
    /// The raw header block.
    pub header: Vec<u8>,
    /// The first few kilobytes of the raw message, when a preview was requested.
    pub preview: Option<Vec<u8>>,
}

/// A downloaded message.
#[derive(Debug, Clone)]
pub struct Fetched {
    pub raw: Vec<u8>,
    pub flags: Flags,
    pub internal_date: Option<DateTime<FixedOffset>>,
    /// Only the first [`PARTIAL_BYTES`] were downloaded.
    pub truncated: bool,
}

struct XOAuth2 {
    payload: Zeroizing<String>,
    sent: bool,
}

impl async_imap::Authenticator for XOAuth2 {
    type Response = Vec<u8>;

    fn process(&mut self, _challenge: &[u8]) -> Self::Response {
        // The token is offered exactly once. If the server answers with an error challenge
        // we reply with an empty line, which makes it finish with its error instead of
        // being handed the token a second time.
        if self.sent {
            Vec::new()
        } else {
            self.sent = true;
            self.payload.as_bytes().to_vec()
        }
    }
}

/// An authenticated IMAP connection to one account.
pub struct Session {
    inner: async_imap::Session<TlsStream<TcpStream>>,
    provider: Provider,
    folders: Option<Vec<Folder>>,
}

impl Session {
    /// Open a verified TLS connection and read the server's greeting. Nothing is sent yet.
    async fn open(
        provider: Provider,
        tls: Arc<ClientConfig>,
    ) -> Result<async_imap::Client<TlsStream<TcpStream>>> {
        let (host, port) = provider.imap();
        let server_name = ServerName::try_from(host).map_err(|e| Error::Network(e.to_string()))?;

        let stream = timed("connecting to the mail server", CONNECT_TIMEOUT, async {
            let tcp = TcpStream::connect((host, port)).await?;
            tcp.set_nodelay(true)?;
            TlsConnector::from(tls).connect(server_name, tcp).await
        })
        .await
        .map_err(|e| match e {
            Error::Timeout(what) => Error::Timeout(what),
            other => Error::Network(format!(
                "could not connect securely to {host}:{port}: {other}"
            )),
        })?;

        let mut client = async_imap::Client::new(stream);
        timed(
            "waiting for the mail server greeting",
            CONNECT_TIMEOUT,
            client.read_response(),
        )
        .await
        .map_err(|e| Error::Network(format!("no greeting from {host}: {e}")))?
        .ok_or_else(|| Error::Network(format!("{host} closed the connection")))?;
        Ok(client)
    }

    pub async fn connect(
        account: &Account,
        credentials: Credentials,
        tls: Arc<ClientConfig>,
    ) -> Result<Self> {
        let client = Self::open(account.provider, tls).await?;
        let name = &account.name;
        let inner = timed("signing in to the mail server", COMMAND_TIMEOUT, async {
            match credentials {
                Credentials::Password(password) => client
                    .login(&account.address, password.as_str())
                    .await
                    .map_err(|(e, _)| Error::auth(format!(
                        "Sign-in to {name} failed ({e}). The app password may have been revoked; the user can replace it with: mail-mcp add-gmail {name} {}",
                        account.address
                    ))),
                Credentials::AccessToken(token) => {
                    let payload = xoauth2_payload(&account.address, &token);
                    client
                        .authenticate("XOAUTH2", XOAuth2 { payload, sent: false })
                        .await
                        .map_err(|(e, _)| Error::auth(format!(
                            "Sign-in to {name} failed ({e}). The user may need to sign in again with: mail-mcp auth {name}"
                        )))
                }
            }
        })
        .await?;

        Ok(Self {
            inner,
            provider: account.provider,
            folders: None,
        })
    }

    pub fn is_gmail(&self) -> bool {
        self.provider == Provider::Gmail
    }

    /// End the session politely. Failures do not matter: the connection is dropped anyway.
    pub async fn logout(mut self) {
        let _ = tokio::time::timeout(Duration::from_secs(5), self.inner.logout()).await;
    }

    // ----------------------------------------------------------------- folders

    pub async fn folders(&mut self) -> Result<&[Folder]> {
        if self.folders.is_none() {
            let names: Vec<async_imap::types::Name> =
                timed("listing folders", COMMAND_TIMEOUT, async {
                    let stream = self.inner.list(Some(""), Some("*")).await?;
                    stream.try_collect().await
                })
                .await?;
            let folders = names
                .iter()
                .map(|name| {
                    let mut special = None;
                    let mut selectable = true;
                    for attribute in name.attributes() {
                        match attribute {
                            NameAttribute::NoSelect => selectable = false,
                            NameAttribute::Drafts => special = Some(Special::Drafts),
                            NameAttribute::Sent => special = Some(Special::Sent),
                            NameAttribute::Trash => special = Some(Special::Trash),
                            NameAttribute::Junk => special = Some(Special::Junk),
                            NameAttribute::All => special = Some(Special::All),
                            NameAttribute::Archive => special = Some(Special::Archive),
                            NameAttribute::Flagged => special = Some(Special::Flagged),
                            _ => {}
                        }
                    }
                    Folder {
                        name: mutf7::decode(name.name()),
                        special,
                        selectable,
                    }
                })
                .collect();
            self.folders = Some(folders);
        }
        Ok(self.folders.as_deref().unwrap_or_default())
    }

    /// The real name of a special folder on this account.
    pub async fn special(&mut self, special: Special) -> Result<String> {
        // Gmail has no archive folder: archiving means "only in All Mail".
        let wanted = if self.is_gmail() && special == Special::Archive {
            Special::All
        } else {
            special
        };
        let provider = self.provider;
        let folders = self.folders().await?;
        if let Some(folder) = folders.iter().find(|f| f.special == Some(wanted)) {
            return Ok(folder.name.clone());
        }
        for fallback in wanted.fallbacks(provider) {
            // Some UK and German Gmail accounts use "[Google Mail]" as the prefix.
            let alternative = fallback.replacen("[Gmail]/", "[Google Mail]/", 1);
            if let Some(folder) = folders.iter().find(|f| {
                f.name.eq_ignore_ascii_case(fallback) || f.name.eq_ignore_ascii_case(&alternative)
            }) {
                return Ok(folder.name.clone());
            }
        }
        Err(Error::invalid(format!(
            "This account has no '{}' folder",
            special.label()
        )))
    }

    /// Turn what a tool call said ("inbox", "trash", "Receipts/2026") into a real folder name.
    pub async fn resolve(&mut self, folder: &str) -> Result<String> {
        let folder = folder.trim();
        if folder.is_empty() || folder.eq_ignore_ascii_case("inbox") {
            return Ok("INBOX".to_owned());
        }
        if let Some(found) = self.find_folder(folder).await? {
            return Ok(found);
        }
        match Special::from_alias(folder) {
            Some(special) => self.special(special).await,
            None => {
                let names: Vec<&str> = self
                    .folders()
                    .await?
                    .iter()
                    .take(100)
                    .map(|f| f.name.as_str())
                    .collect();
                Err(Error::invalid(format!(
                    "No folder named '{folder}'. Existing folders: {}",
                    names.join(", ")
                )))
            }
        }
    }

    /// Case-insensitive lookup of an existing folder's exact name.
    pub async fn find_folder(&mut self, folder: &str) -> Result<Option<String>> {
        let wanted = folder.to_lowercase();
        Ok(self
            .folders()
            .await?
            .iter()
            .find(|f| f.name.to_lowercase() == wanted)
            .map(|f| f.name.clone()))
    }

    /// Is `folder` (a real name) this account's folder for the given role?
    pub async fn is_special(&mut self, folder: &str, special: Special) -> Result<bool> {
        match self.special(special).await {
            Ok(name) => Ok(name.eq_ignore_ascii_case(folder)),
            Err(Error::Invalid(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Open a folder (a real name from [`Session::resolve`]).
    pub async fn select(&mut self, folder: &str, read_only: bool) -> Result<()> {
        let wire = wire_name(folder)?;
        timed("opening the folder", COMMAND_TIMEOUT, async {
            if read_only {
                self.inner.examine(&wire).await
            } else {
                self.inner.select(&wire).await
            }
        })
        .await
        .map(drop)
        .map_err(|e| match e {
            Error::Imap(inner) => Error::invalid(format!("Cannot open folder '{folder}': {inner}")),
            other => other,
        })
    }

    pub async fn create(&mut self, folder: &str) -> Result<()> {
        if folder.trim() != folder {
            return Err(Error::invalid(
                "Folder names cannot start or end with a space",
            ));
        }
        let wire = wire_name(folder)?;
        timed(
            "creating the folder",
            COMMAND_TIMEOUT,
            self.inner.create(&wire),
        )
        .await?;
        // Subscribing makes the folder show up in other mail apps; not essential.
        let _ = timed(
            "subscribing to the folder",
            COMMAND_TIMEOUT,
            self.inner.subscribe(&wire),
        )
        .await;
        self.folders = None;
        Ok(())
    }

    // ----------------------------------------------------------------- messages

    /// UIDs matching every term, oldest first.
    pub async fn search(&mut self, terms: &[Term]) -> Result<Vec<u32>> {
        let query = render_search(terms)?;
        let found = timed("searching", COMMAND_TIMEOUT, self.inner.uid_search(&query)).await?;
        let mut uids: Vec<u32> = found.into_iter().collect();
        uids.sort_unstable();
        Ok(uids)
    }

    async fn fetch(&mut self, uids: &UidSet, items: &str) -> Result<Vec<Fetch>> {
        let all: Vec<Fetch> = timed("downloading from the mail server", COMMAND_TIMEOUT, async {
            let stream = self.inner.uid_fetch(uids.wire(), items).await?;
            stream.try_collect().await
        })
        .await?;
        // Servers may volunteer FETCH data about other messages; keep only what was asked for.
        Ok(all
            .into_iter()
            .filter(|f| f.uid.is_some_and(|uid| uids.contains(uid)))
            .collect())
    }

    /// Headers (and optionally the start of the body) for a listing.
    pub async fn summaries(&mut self, uids: &UidSet, with_preview: bool) -> Result<Vec<Summary>> {
        let mut items = String::from("(UID FLAGS BODY.PEEK[HEADER]");
        if self.is_gmail() {
            items.push_str(" X-GM-LABELS");
        }
        if with_preview {
            items.push_str(&format!(" BODY.PEEK[]<0.{PREVIEW_BYTES}>"));
        }
        items.push(')');
        let fetched = self.fetch(uids, &items).await?;
        Ok(fetched
            .iter()
            .filter_map(|f| {
                Some(Summary {
                    uid: f.uid?,
                    flags: Flags::of(f),
                    labels: gmail_labels(f),
                    header: f.header().unwrap_or_default().to_vec(),
                    preview: f.body().map(<[u8]>::to_vec),
                })
            })
            .collect())
    }

    /// Gmail labels on one message.
    pub async fn labels(&mut self, uid: u32) -> Result<Vec<String>> {
        let fetched = self
            .fetch(&UidSet::single(uid)?, "(UID X-GM-LABELS)")
            .await?;
        Ok(fetched.first().map(gmail_labels).unwrap_or_default())
    }

    /// Download one message. Messages larger than `full_limit` are refused unless
    /// `allow_partial`, in which case only their first [`PARTIAL_BYTES`] are fetched.
    pub async fn message(
        &mut self,
        uid: u32,
        full_limit: u32,
        allow_partial: bool,
    ) -> Result<Fetched> {
        let set = UidSet::single(uid)?;
        let missing = || Error::invalid(format!("No message with uid {uid} in this folder"));

        let info = self.fetch(&set, "(UID RFC822.SIZE)").await?;
        let size = info.first().ok_or_else(missing)?.size;
        // An unknown size is treated as too big.
        let truncated = size.is_none_or(|s| s > full_limit);
        if truncated && !allow_partial {
            return Err(Error::invalid(match size {
                Some(s) => format!("That email is too large ({} MB)", s / (1024 * 1024)),
                None => "That email is too large (size unknown)".to_owned(),
            }));
        }
        let section = if truncated {
            format!("BODY.PEEK[]<0.{PARTIAL_BYTES}>")
        } else {
            "BODY.PEEK[]".to_owned()
        };
        let fetched = self
            .fetch(&set, &format!("(UID FLAGS INTERNALDATE {section})"))
            .await?;
        let fetch = fetched.first().ok_or_else(missing)?;
        let raw = fetch.body().ok_or_else(missing)?.to_vec();
        Ok(Fetched {
            raw,
            flags: Flags::of(fetch),
            internal_date: fetch.internal_date(),
            truncated,
        })
    }

    /// Move messages to another folder (a real name) of the same account.
    pub async fn move_to(&mut self, uids: &UidSet, destination: &str) -> Result<()> {
        let wire = wire_name(destination)?;
        timed(
            "moving messages",
            COMMAND_TIMEOUT,
            self.inner.uid_mv(uids.wire(), &wire),
        )
        .await
    }

    async fn store(&mut self, uids: &UidSet, change: &str) -> Result<()> {
        timed("updating messages", COMMAND_TIMEOUT, async {
            let stream = self.inner.uid_store(uids.wire(), change).await?;
            stream.try_collect::<Vec<Fetch>>().await
        })
        .await
        .map(drop)
    }

    pub async fn set_seen(&mut self, uids: &UidSet, seen: bool) -> Result<()> {
        self.store(
            uids,
            if seen {
                "+FLAGS (\\Seen)"
            } else {
                "-FLAGS (\\Seen)"
            },
        )
        .await
    }

    pub async fn set_flagged(&mut self, uids: &UidSet, flagged: bool) -> Result<()> {
        self.store(
            uids,
            if flagged {
                "+FLAGS (\\Flagged)"
            } else {
                "-FLAGS (\\Flagged)"
            },
        )
        .await
    }

    /// Add or remove Gmail labels.
    pub async fn change_labels(
        &mut self,
        uids: &UidSet,
        add: bool,
        labels: &[String],
    ) -> Result<()> {
        if labels.is_empty() {
            return Ok(());
        }
        let rendered = labels
            .iter()
            .map(|l| gmail_label_wire(l))
            .collect::<Result<Vec<_>>>()?
            .join(" ");
        let sign = if add { '+' } else { '-' };
        self.store(uids, &format!("{sign}X-GM-LABELS ({rendered})"))
            .await
    }

    /// Save a message into a folder (a real name).
    pub async fn append(
        &mut self,
        folder: &str,
        flags: Flags,
        date: Option<DateTime<FixedOffset>>,
        raw: &[u8],
    ) -> Result<()> {
        let wire = wire_name(folder)?;
        let mut names = Vec::new();
        if flags.seen {
            names.push("\\Seen");
        }
        if flags.flagged {
            names.push("\\Flagged");
        }
        if flags.draft {
            names.push("\\Draft");
        }
        let flag_list = format!("({})", names.join(" "));
        let date = date.map(|d| format!("\"{}\"", d.format("%d-%b-%Y %H:%M:%S %z")));
        timed(
            "saving the message",
            COMMAND_TIMEOUT,
            self.inner
                .append(&wire, Some(&flag_list), date.as_deref(), raw),
        )
        .await
    }
}

fn gmail_labels(fetch: &Fetch) -> Vec<String> {
    fetch
        .gmail_labels()
        .map(|labels| labels.iter().map(|l| mutf7::decode(l)).collect())
        .unwrap_or_default()
}

/// A Gmail label as written in a STORE command. The three system labels that are useful to
/// set are written as atoms; everything else is a quoted, encoded string.
fn gmail_label_wire(label: &str) -> Result<String> {
    Ok(match label.to_ascii_lowercase().as_str() {
        "inbox" => "\\Inbox".to_owned(),
        "starred" => "\\Starred".to_owned(),
        "important" => "\\Important".to_owned(),
        _ => quote(&wire_name(label)?)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_escapes_and_rejects() {
        assert_eq!(quote("plain").expect("plain"), "\"plain\"");
        assert_eq!(quote(r#"a "b" \c"#).expect("escaped"), r#""a \"b\" \\c""#);
        assert!(quote("line\r\nA1 LOGOUT").is_err());
        assert!(quote("nul\0").is_err());
        assert!(quote(&"x".repeat(1001)).is_err());
    }

    #[test]
    fn search_is_built_from_quoted_terms() {
        let date = NaiveDate::from_ymd_opt(2026, 1, 5).expect("date");
        let query = render_search(&[
            Term::Unseen,
            Term::From("boss@example.com".into()),
            Term::Since(date),
            Term::Subject(r#"say "hi""#.into()),
        ])
        .expect("render");
        assert_eq!(
            query,
            r#"UNSEEN FROM "boss@example.com" SINCE 5-Jan-2026 SUBJECT "say \"hi\"""#
        );
        assert_eq!(render_search(&[]).expect("all"), "ALL");
    }

    #[test]
    fn search_cannot_be_broken_out_of() {
        // An attempt to close the quote and add criteria stays inside the string.
        let query = render_search(&[Term::Text(r#"x" OR ALL DELETED ""#.into())]).expect("render");
        assert_eq!(query, r#"TEXT "x\" OR ALL DELETED \"""#);
        assert!(render_search(&[Term::Text("x\r\nA2 DELETE INBOX".into())]).is_err());
    }

    #[test]
    fn non_ascii_search_declares_a_charset() {
        let query = render_search(&[Term::Subject("Rechnung für März".into())]).expect("render");
        assert_eq!(query, "CHARSET UTF-8 SUBJECT \"Rechnung für März\"");
    }

    #[test]
    fn thread_search_renders_or() {
        let id = "<abc@example.com>".to_owned();
        let query = render_search(&[Term::Or(
            Box::new(Term::Header("MESSAGE-ID", id.clone())),
            Box::new(Term::Header("REFERENCES", id)),
        )])
        .expect("render");
        assert_eq!(
            query,
            r#"OR HEADER MESSAGE-ID "<abc@example.com>" HEADER REFERENCES "<abc@example.com>""#
        );
    }

    #[test]
    fn uid_sets_are_validated() {
        assert_eq!(UidSet::new(&[3, 1, 3, 2]).expect("set").wire(), "3,1,2");
        assert!(UidSet::new(&[]).is_err());
        assert!(UidSet::new(&[0]).is_err());
        let too_many: Vec<u32> = (1..=501).collect();
        assert!(UidSet::new(&too_many).is_err());
    }

    #[test]
    fn folder_names_are_encoded_and_checked() {
        assert_eq!(
            wire_name("Été/Reçus").expect("name"),
            "&AMk-t&AOk-/Re&AOc-us"
        );
        assert!(wire_name("").is_err());
        assert!(wire_name("a\nb").is_err());
        assert!(wire_name(&"x".repeat(201)).is_err());
    }

    #[test]
    fn gmail_labels_are_atoms_or_quoted() {
        assert_eq!(gmail_label_wire("Inbox").expect("inbox"), "\\Inbox");
        assert_eq!(
            gmail_label_wire("Bills/Energy").expect("label"),
            "\"Bills/Energy\""
        );
        // A user label that merely looks like a system flag is quoted, never an atom.
        assert_eq!(gmail_label_wire("\\Draft").expect("label"), "\"\\\\Draft\"");
        assert!(gmail_label_wire("a\r\nb").is_err());
    }

    #[test]
    fn aliases_map_to_special_folders() {
        assert_eq!(Special::from_alias("Bin"), Some(Special::Trash));
        assert_eq!(Special::from_alias("SPAM"), Some(Special::Junk));
        assert_eq!(Special::from_alias("Receipts"), None);
    }

    /// Live check that both providers' IMAP servers pass certificate verification and
    /// greet us. No sign-in is attempted. Run with `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore = "contacts the Outlook and Gmail IMAP servers"]
    async fn imap_servers_pass_tls_verification_and_greet() {
        for provider in [Provider::Outlook, Provider::Gmail] {
            let tls = tls_config().expect("tls");
            let opened = Session::open(provider, tls).await;
            assert!(opened.is_ok(), "{provider:?}: {:?}", opened.err());
        }
    }

    #[test]
    fn tls_config_builds() {
        assert!(tls_config().is_ok());
    }
}
