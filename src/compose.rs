//! Building outgoing mail, and describing it for the approval dialog.
//!
//! Outgoing messages are plain text only, so nothing can hide in markup. The same parsed
//! recipient list feeds the message headers, the SMTP envelope and the dialog, so what the
//! user approves is exactly who receives it.

use mail_builder::MessageBuilder;
use mail_builder::headers::address::Address;
use mail_parser::Message;

use crate::attach::LocalFile;
use crate::config::{Account, Provider, validate_address};
use crate::error::{Error, Result};
use crate::html::link_destination;
use crate::message::{self, Envelope, Mailbox};
use crate::sanitize::{clean, oneline, safe_filename, truncate_chars};

pub const MAX_RECIPIENTS: usize = 50;
pub const MAX_ATTACHMENT_BYTES: u64 = 25 * 1024 * 1024;
const MAX_SUBJECT_CHARS: usize = 500;
const MAX_BODY_CHARS: usize = 500_000;
/// How much message text the approval dialog shows before cutting off.
const DIALOG_TEXT_CHARS: usize = 6000;
const MAX_REFERENCES: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    New,
    Reply,
    ReplyAll,
    Forward,
}

impl Mode {
    pub fn parse(mode: &str) -> Result<Self> {
        match mode.trim().to_ascii_lowercase().as_str() {
            "" | "new" => Ok(Self::New),
            "reply" => Ok(Self::Reply),
            "reply_all" | "replyall" | "reply-all" => Ok(Self::ReplyAll),
            "forward" => Ok(Self::Forward),
            other => Err(Error::invalid(format!(
                "mode must be new, reply, reply_all or forward (got '{other}')"
            ))),
        }
    }

    pub const fn needs_original(self) -> bool {
        !matches!(self, Self::New)
    }
}

/// What the caller asked for.
#[derive(Debug, Clone)]
pub struct Request {
    pub mode: Mode,
    pub to: String,
    pub cc: String,
    pub bcc: String,
    pub subject: String,
    pub body: String,
    pub quote_original: bool,
    pub add_signature: bool,
    pub include_original_attachments: bool,
}

/// Parse a comma-separated recipient list as written in a tool call.
pub fn parse_recipients(input: &str) -> Result<Vec<Mailbox>> {
    let input = input.trim();
    if input.is_empty() {
        return Ok(Vec::new());
    }
    if input.chars().any(char::is_control) {
        return Err(Error::invalid(
            "Recipient lists cannot contain line breaks or control characters",
        ));
    }
    // Let a real header parser do the work, then insist it understood everything.
    let header = format!("To: {input}\r\n\r\n");
    let parsed = message::parse(header.as_bytes())?;
    let found = message::mailboxes(parsed.root().headers().to());
    // Every comma-separated entry must have produced exactly one mailbox, and there must be
    // no stray `@` (as in a display name dressed up to look like another address).
    let entries = {
        let (mut count, mut in_quotes, mut has_text) = (0usize, false, false);
        for c in input.chars() {
            match c {
                '"' => in_quotes = !in_quotes,
                ',' if !in_quotes => {
                    count += usize::from(has_text);
                    has_text = false;
                    continue;
                }
                _ => {}
            }
            has_text |= !c.is_whitespace();
        }
        count + usize::from(has_text)
    };
    if found.is_empty() || found.len() != entries || found.len() != input.matches('@').count() {
        return Err(Error::invalid(format!(
            "Could not read every recipient in '{}'. Write plain addresses separated by commas.",
            oneline(input, 200)
        )));
    }
    for mailbox in &found {
        validate_address(&mailbox.address)?;
    }
    Ok(found)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentOrigin {
    /// Read from the user's disk.
    Local,
    /// Carried over from the message being forwarded.
    Original,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    pub name: String,
    pub content_type: String,
    pub data: Vec<u8>,
    pub origin: AttachmentOrigin,
    /// Where a local file was read from.
    pub source: Option<std::path::PathBuf>,
}

/// The original message quoted beneath a reply or forward.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quoted {
    /// One-line description for the dialog, e.g. "the original message from Ann <a@b> dated ...".
    pub summary: String,
    /// The block as it appears in the message.
    pub block: String,
}

/// A message we composed, ready to save as a draft or send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    pub from: Mailbox,
    pub to: Vec<Mailbox>,
    pub cc: Vec<Mailbox>,
    pub bcc: Vec<Mailbox>,
    pub subject: String,
    /// What the caller wrote, plus the signature.
    pub own_text: String,
    pub quoted: Option<Quoted>,
    /// Without angle brackets.
    pub message_id: String,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub attachments: Vec<Attachment>,
    pub warnings: Vec<String>,
}

fn new_message_id(domain: &str) -> Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|e| Error::Network(format!("no randomness available: {e}")))?;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Ok(format!("{hex}@{domain}"))
}

fn prefixed(subject: &str, prefix: &str) -> String {
    let subject = subject.trim();
    if subject.to_lowercase().starts_with(&prefix.to_lowercase()) {
        subject.to_owned()
    } else {
        format!("{prefix} {subject}").trim().to_owned()
    }
}

fn push_unique(list: &mut Vec<Mailbox>, seen: &mut Vec<String>, mailbox: Mailbox) {
    let key = mailbox.address.to_lowercase();
    if !seen.contains(&key) {
        seen.push(key);
        list.push(mailbox);
    }
}

impl Outgoing {
    /// Compose a message. `original` is the message being replied to or forwarded;
    /// `local_files` have already been read from the allowed folders.
    pub fn build(
        account: &Account,
        request: &Request,
        original: Option<&Message<'_>>,
        local_files: Vec<LocalFile>,
    ) -> Result<Self> {
        let original = match (request.mode.needs_original(), original) {
            (true, None) => {
                return Err(Error::invalid(
                    "Replying or forwarding needs the original message (original_uid)",
                ));
            }
            (true, Some(message)) => Some(message.root()),
            (false, _) => None,
        };
        let original_envelope = original.map(Envelope::of);
        let own_addresses = account.own_addresses();
        let mut warnings = Vec::new();

        let mut to_input = parse_recipients(&request.to)?;
        let mut cc_input = parse_recipients(&request.cc)?;
        let bcc_input = parse_recipients(&request.bcc)?;

        let mut subject = oneline(&request.subject, MAX_SUBJECT_CHARS);
        let mut in_reply_to = None;
        let mut references = Vec::new();

        if let (Some(message), Some(envelope)) = (original, &original_envelope) {
            match request.mode {
                Mode::Reply | Mode::ReplyAll => {
                    if to_input.is_empty() {
                        to_input = if envelope.reply_to.is_empty() {
                            envelope.from.clone()
                        } else {
                            envelope.reply_to.clone()
                        };
                    }
                    if request.mode == Mode::ReplyAll {
                        cc_input.extend(
                            envelope
                                .to
                                .iter()
                                .chain(&envelope.cc)
                                .filter(|m| !own_addresses.contains(&m.address.to_lowercase()))
                                .cloned(),
                        );
                    }
                    if subject.is_empty() {
                        subject = prefixed(&envelope.subject, "Re:");
                    }
                    if let Some(id) = &envelope.message_id {
                        in_reply_to = Some(id.clone());
                        let skip = envelope.references.len().saturating_sub(MAX_REFERENCES);
                        references = envelope.references[skip..].to_vec();
                        references.push(id.clone());
                    }
                    // The reply goes to whoever the original says it should; make sure the
                    // user sees if that looks wrong.
                    warnings.extend(message::sender_warnings(message, account.provider));
                }
                Mode::Forward => {
                    if subject.is_empty() {
                        subject = prefixed(&envelope.subject, "Fwd:");
                    }
                }
                Mode::New => {}
            }
        }

        // One recipient list, de-duplicated across To, Cc and Bcc, with every address checked.
        let (mut to, mut cc, mut bcc, mut seen) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for mailbox in to_input {
            push_unique(&mut to, &mut seen, mailbox);
        }
        for mailbox in cc_input {
            push_unique(&mut cc, &mut seen, mailbox);
        }
        for mailbox in bcc_input {
            push_unique(&mut bcc, &mut seen, mailbox);
        }
        for mailbox in to.iter().chain(&cc).chain(&bcc) {
            validate_address(&mailbox.address)?;
        }
        if seen.is_empty() {
            return Err(Error::invalid("No recipient given"));
        }
        if seen.len() > MAX_RECIPIENTS {
            return Err(Error::invalid(format!(
                "{} recipients is over the limit of {MAX_RECIPIENTS}",
                seen.len()
            )));
        }

        // The text is cleaned before it is shown or sent, so the dialog and the message agree.
        let (body, cut) = truncate_chars(&request.body, MAX_BODY_CHARS);
        if cut {
            return Err(Error::invalid("The message text is too long"));
        }
        let mut own_text = clean(body).text;
        if request.add_signature
            && let Some(signature) = account
                .signature
                .as_deref()
                .filter(|s| !s.trim().is_empty())
        {
            own_text.push_str("\n\n-- \n");
            own_text.push_str(&clean(signature).text);
        }

        let quoted = match (original, &original_envelope) {
            (Some(message), Some(envelope))
                if request.mode == Mode::Forward || request.quote_original =>
            {
                Some(quote(request.mode, message, envelope))
            }
            _ => None,
        };

        let mut attachments: Vec<Attachment> = local_files
            .into_iter()
            .map(|file| Attachment {
                name: safe_filename(&file.name),
                content_type: file.content_type.to_owned(),
                data: file.data,
                origin: AttachmentOrigin::Local,
                source: Some(file.path),
            })
            .collect();
        if let Some(message) = original
            && request.mode == Mode::Forward
            && request.include_original_attachments
        {
            let mut total: u64 = attachments.iter().map(|a| a.data.len() as u64).sum();
            for part in message.attachments() {
                let mut name = safe_filename(part.attachment_name().unwrap_or("attachment"));
                let mut content_type = message::content_type_of(&part);
                if part.is_message() {
                    // An attached email is forwarded whole, as a file.
                    content_type = "application/octet-stream".to_owned();
                    if !name.to_lowercase().ends_with(".eml") {
                        name.push_str(".eml");
                    }
                }
                let data = part.decoded().into_owned();
                total += data.len() as u64;
                if total > MAX_ATTACHMENT_BYTES {
                    return Err(Error::invalid("Attachments are limited to 25 MB in total"));
                }
                attachments.push(Attachment {
                    name,
                    content_type,
                    data,
                    origin: AttachmentOrigin::Original,
                    source: None,
                });
            }
        }

        Ok(Self {
            from: Mailbox {
                name: account.display_name.clone(),
                address: account.address.clone(),
            },
            to,
            cc,
            bcc,
            subject,
            own_text,
            quoted,
            message_id: new_message_id(account.domain())?,
            in_reply_to,
            references,
            attachments,
            warnings,
        })
    }

    /// Everyone who will receive the message. This is the SMTP envelope.
    pub fn recipients(&self) -> Vec<String> {
        self.to
            .iter()
            .chain(&self.cc)
            .chain(&self.bcc)
            .map(|m| m.address.clone())
            .collect()
    }

    pub fn has_local_attachments(&self) -> bool {
        self.attachments
            .iter()
            .any(|a| a.origin == AttachmentOrigin::Local)
    }

    fn full_text(&self) -> String {
        match &self.quoted {
            Some(quoted) => format!("{}\n\n{}", self.own_text, quoted.block),
            None => self.own_text.clone(),
        }
    }

    /// The message as bytes. Drafts keep their Bcc header; a message handed to SMTP must
    /// not, or every recipient would see the blind copies.
    pub fn to_bytes(&self, with_bcc: bool) -> Result<Vec<u8>> {
        let address = |m: &Mailbox| Address::new_address(m.name.clone(), m.address.clone());
        let list = |ms: &[Mailbox]| Address::new_list(ms.iter().map(address).collect());

        let mut builder = MessageBuilder::new()
            .from(address(&self.from))
            .subject(self.subject.as_str())
            .message_id(self.message_id.as_str())
            .text_body(self.full_text());
        if !self.to.is_empty() {
            builder = builder.to(list(&self.to));
        }
        if !self.cc.is_empty() {
            builder = builder.cc(list(&self.cc));
        }
        if with_bcc && !self.bcc.is_empty() {
            builder = builder.bcc(list(&self.bcc));
        }
        if let Some(id) = &self.in_reply_to {
            builder = builder
                .in_reply_to(id.as_str())
                .references(self.references.clone());
        }
        for attachment in &self.attachments {
            builder = builder.attachment(
                attachment.content_type.as_str(),
                attachment.name.as_str(),
                attachment.data.as_slice(),
            );
        }
        builder
            .write_to_vec()
            .map_err(|e| Error::invalid(format!("Could not build the message: {e}")))
    }

    /// The text of the approval dialog.
    pub fn describe(&self, action: &str, account: &Account) -> String {
        let mut lines = vec![
            format!(
                "{action} from account '{}' ({})",
                account.name, account.address
            ),
            String::new(),
        ];
        describe_recipients(&mut lines, &self.to, &self.cc, &self.bcc);
        lines.push(format!("Subject: {}", oneline(&self.subject, 200)));
        if self.attachments.is_empty() {
            lines.push("Attachments: none".to_owned());
        } else {
            lines.push(format!("Attachments ({}):", self.attachments.len()));
            for a in &self.attachments {
                let from = match (&a.source, a.origin) {
                    (Some(path), _) => format!(
                        "from your disk: {}",
                        oneline(&path.display().to_string(), 200)
                    ),
                    (None, _) => "carried over from the original email".to_owned(),
                };
                lines.push(format!(
                    "  {} ({} KB, {from})",
                    oneline(&a.name, 100),
                    a.data.len().div_ceil(1024)
                ));
            }
        }
        let links = link_hosts(&self.own_text);
        if !links.is_empty() {
            lines.push(format!("Links in the text go to: {}", links.join(", ")));
        }
        for warning in &self.warnings {
            lines.push(format!("WARNING: {}", oneline(warning, 300)));
        }
        lines.push(String::new());
        lines.push("--- message text ---".to_owned());
        lines.push(dialog_text(&self.own_text));
        if let Some(quoted) = &self.quoted {
            lines.push(String::new());
            lines.push(format!(
                "--- followed by {} (not repeated here) ---",
                quoted.summary
            ));
        }
        lines.join("\n")
    }
}

fn quote(mode: Mode, message: mail_parser::MessageRef<'_>, envelope: &Envelope) -> Quoted {
    let text = message::body(message).text;
    let from = envelope.sender_line();
    let date = if envelope.date.is_empty() {
        "an unknown date".to_owned()
    } else {
        envelope.date.clone()
    };
    let summary = format!(
        "the original message from {} dated {} ({} characters)",
        if from.is_empty() {
            "an unknown sender".to_owned()
        } else {
            from.clone()
        },
        date,
        text.chars().count()
    );
    let block = if mode == Mode::Forward {
        format!(
            "---------- Forwarded message ---------\nFrom: {from}\nDate: {date}\nSubject: {}\nTo: {}\n\n{text}",
            envelope.subject,
            message::display_list(&envelope.to, 500),
        )
    } else {
        let quoted: Vec<String> = text.lines().map(|line| format!("> {line}")).collect();
        format!("On {date}, {from} wrote:\n{}", quoted.join("\n"))
    };
    Quoted { summary, block }
}

fn describe_recipients(lines: &mut Vec<String>, to: &[Mailbox], cc: &[Mailbox], bcc: &[Mailbox]) {
    lines.push(format!("Recipients ({}):", to.len() + cc.len() + bcc.len()));
    for (kind, list) in [("To", to), ("Cc", cc), ("Bcc", bcc)] {
        for mailbox in list {
            // The address comes first and in full: that is where the mail actually goes.
            let name = mailbox
                .name
                .as_deref()
                .map(|n| oneline(n, 60))
                .filter(|n| !n.is_empty());
            lines.push(match name {
                Some(name) => format!(
                    "  {kind}: {}  (shown as \"{name}\")",
                    oneline(&mailbox.address, 254)
                ),
                None => format!("  {kind}: {}", oneline(&mailbox.address, 254)),
            });
        }
    }
}

/// Hosts of the web links written in a piece of text.
fn link_hosts(text: &str) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    for word in text
        .split(|c: char| c.is_whitespace() || matches!(c, '<' | '>' | '"' | '(' | ')' | '[' | ']'))
    {
        let lower = word.to_ascii_lowercase();
        if (lower.starts_with("http://") || lower.starts_with("https://"))
            && let Some(host) = link_destination(word)
            && !hosts.contains(&host)
            && hosts.len() < 15
        {
            hosts.push(host);
        }
    }
    hosts
}

/// Message text for the dialog: long runs of blank lines or spaces are made visible (they
/// can be used to push text out of view), and the text is cut at a stated limit.
fn dialog_text(text: &str) -> String {
    let mut out = String::new();
    let mut blank_run = 0usize;
    let flush = |out: &mut String, run: usize| {
        if run > 2 {
            out.push_str(&format!("[{run} blank lines]\n"));
        } else {
            out.push_str(&"\n".repeat(run));
        }
    };
    for line in text.lines() {
        if line.trim().is_empty() {
            blank_run += 1;
            continue;
        }
        flush(&mut out, blank_run);
        blank_run = 0;
        let mut spaces = 0usize;
        for c in line.chars() {
            if c == ' ' || c == '\t' || c == '\u{a0}' {
                spaces += 1;
                continue;
            }
            if spaces > 8 {
                out.push_str(&format!(" [{spaces} spaces] "));
            } else {
                out.push_str(&" ".repeat(spaces));
            }
            spaces = 0;
            out.push(c);
        }
        out.push('\n');
    }
    let out = out.trim_end();
    let total = out.chars().count();
    let (shown, cut) = truncate_chars(out, DIALOG_TEXT_CHARS);
    if cut {
        format!(
            "{shown}\n[... {} MORE CHARACTERS NOT SHOWN. Refuse unless you expected a message this long.]",
            total - DIALOG_TEXT_CHARS
        )
    } else {
        shown.to_owned()
    }
}

// ---------------------------------------------------------------------------------------
// Sending a draft that already exists in the mailbox.

/// An existing draft, checked and made ready to hand to SMTP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedDraft {
    /// The message with Bcc and other delivery-affecting headers removed and a fresh Date.
    pub bytes: Vec<u8>,
    pub recipients: Vec<String>,
    pub subject: String,
    pub message_id: String,
    /// The text of the approval dialog.
    pub description: String,
}

/// Check a draft fetched from the mailbox and prepare it for sending.
pub fn prepare_draft(
    account: &Account,
    raw: &[u8],
    marked_as_draft: bool,
) -> Result<PreparedDraft> {
    let parsed = message::parse(raw)?;
    let root = parsed.root();
    let envelope = Envelope::of(root);
    let headers = root.headers();
    let bcc = message::mailboxes(headers.bcc());

    let own = account.own_addresses();
    match envelope.from.as_slice() {
        [from] if own.contains(&from.address.to_lowercase()) => {}
        _ => {
            return Err(Error::denied(format!(
                "This draft's From is '{}', not account '{}': it will not be sent",
                envelope.sender_line(),
                account.name
            )));
        }
    }
    let all: Vec<&Mailbox> = envelope.to.iter().chain(&envelope.cc).chain(&bcc).collect();
    if all.is_empty() {
        return Err(Error::invalid("This draft has no recipients"));
    }
    if all.len() > MAX_RECIPIENTS {
        return Err(Error::invalid(format!(
            "{} recipients is over the limit of {MAX_RECIPIENTS}",
            all.len()
        )));
    }
    let mut recipients: Vec<String> = Vec::new();
    for mailbox in &all {
        validate_address(&mailbox.address)?;
        if !recipients
            .iter()
            .any(|r| r.eq_ignore_ascii_case(&mailbox.address))
        {
            recipients.push(mailbox.address.clone());
        }
    }

    let body = message::body(root);
    let mut warnings = Vec::new();
    if !marked_as_draft {
        warnings.push(
            "This message is not marked as a draft, so it may not be one you wrote".to_owned(),
        );
    }
    // Hidden content in something about to be sent in the user's name is never routine.
    warnings.extend(message::body_warnings(&body.notes));

    let message_id = match envelope.message_id.clone() {
        Some(id) => id,
        None => new_message_id(account.domain())?,
    };
    let mut added = vec![("Date", chrono::Utc::now().to_rfc2822())];
    if envelope.message_id.is_none() {
        added.push(("Message-ID", format!("<{message_id}>")));
    }
    let bytes = rewrite_headers(
        raw,
        |name| {
            let name = name.to_ascii_lowercase();
            // Bcc must not be disclosed; Resent-* would make some servers deliver to more
            // people than the dialog lists; Date is replaced with the time of sending.
            name == "bcc" || name == "date" || name == "return-path" || name.starts_with("resent-")
        },
        &added,
    );

    let mut lines = vec![
        format!(
            "Send this draft from account '{}' ({})",
            account.name, account.address
        ),
        String::new(),
    ];
    describe_recipients(&mut lines, &envelope.to, &envelope.cc, &bcc);
    lines.push(format!("Subject: {}", oneline(&envelope.subject, 200)));
    let attachments = message::attachments(root);
    if attachments.is_empty() {
        lines.push("Attachments: none".to_owned());
    } else {
        let list: Vec<String> = attachments
            .iter()
            .map(|a| format!("{} ({} KB)", a.filename, a.size_bytes.div_ceil(1024)))
            .collect();
        lines.push(format!("Attachments ({}): {}", list.len(), list.join(", ")));
    }
    let mut hosts: Vec<String> = body
        .urls
        .iter()
        .filter_map(|u| link_destination(u))
        .collect();
    hosts.extend(link_hosts(&body.text));
    hosts.sort();
    hosts.dedup();
    if !hosts.is_empty() {
        hosts.truncate(15);
        lines.push(format!("Links and images go to: {}", hosts.join(", ")));
    }
    for warning in &warnings {
        lines.push(format!("WARNING: {}", oneline(warning, 300)));
    }
    lines.push(String::new());
    lines.push("--- message text, as the recipient will see it ---".to_owned());
    lines.push(dialog_text(&body.text));

    Ok(PreparedDraft {
        bytes,
        recipients,
        subject: envelope.subject,
        message_id,
        description: lines.join("\n"),
    })
}

/// Remove the header fields `drop` selects (with their continuation lines) and put `add`
/// at the top. The body is copied untouched.
pub fn rewrite_headers(raw: &[u8], drop: impl Fn(&str) -> bool, add: &[(&str, String)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + 128);
    for (name, value) in add {
        out.extend_from_slice(format!("{name}: {}\r\n", oneline(value, 900)).as_bytes());
    }
    let mut keeping = true;
    let mut rest = raw;
    loop {
        if rest.is_empty() {
            // No body at all: finish the header block properly.
            if !out.ends_with(b"\n") {
                out.extend_from_slice(b"\r\n");
            }
            out.extend_from_slice(b"\r\n");
            return out;
        }
        let end = rest
            .iter()
            .position(|b| *b == b'\n')
            .map_or(rest.len(), |i| i + 1);
        let (line, tail) = rest.split_at(end);
        if line == b"\r\n" || line == b"\n" {
            // The blank line that ends the headers: everything from here is the body.
            out.extend_from_slice(rest);
            return out;
        }
        let continuation = matches!(line.first(), Some(b' ' | b'\t'));
        if !continuation {
            let name = line.split(|b| *b == b':').next().unwrap_or_default();
            keeping = !drop(String::from_utf8_lossy(name).trim());
        }
        if keeping {
            out.extend_from_slice(line);
        }
        rest = tail;
    }
}

/// Used by `copy_to_account`'s dialog: one line per message.
pub fn summary_line(provider: Provider, raw_header: &[u8]) -> String {
    let Ok(parsed) = message::parse(raw_header) else {
        return "(unreadable message)".to_owned();
    };
    let envelope = Envelope::of(parsed.root());
    let flag = if message::sender_warnings(parsed.root(), provider).is_empty() {
        ""
    } else {
        " [sender warning]"
    };
    format!(
        "{} — {}{flag}",
        oneline(&envelope.sender_line(), 80),
        oneline(&envelope.subject, 120)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Provider;

    fn account() -> Account {
        Account {
            name: "hotmail".into(),
            address: "me@example.com".into(),
            provider: Provider::Outlook,
            client_id: Some("01234567-89ab-cdef-0123-456789abcdef".into()),
            display_name: Some("Me Myself".into()),
            signature: Some("Me".into()),
            aliases: vec!["me@alias.example".into()],
            save_sent_copy: false,
        }
    }

    fn request(mode: Mode) -> Request {
        Request {
            mode,
            to: String::new(),
            cc: String::new(),
            bcc: String::new(),
            subject: String::new(),
            body: "Hello there".into(),
            quote_original: true,
            add_signature: true,
            include_original_attachments: false,
        }
    }

    const ORIGINAL: &str = "From: Ann <ann@example.com>\r\nTo: me@example.com, Bob <bob@example.org>\r\nCc: me@alias.example, carol@example.net\r\nSubject: Lunch\r\nDate: Mon, 5 Jan 2026 10:00:00 +0000\r\nMessage-ID: <orig@example.com>\r\nReferences: <first@example.com>\r\n\r\nShall we?\r\nSecond line\r\n";

    fn text_of(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    #[test]
    fn recipients_are_parsed_strictly() {
        let list = parse_recipients("a@example.com, Bob Smith <bob@example.org>").expect("parse");
        assert_eq!(list.len(), 2);
        assert_eq!(list[1].name.as_deref(), Some("Bob Smith"));
        assert!(parse_recipients("").expect("empty").is_empty());
        for bad in [
            "not an address",
            "a@example.com\r\nBcc: evil@example.net",
            "a@example.com, garbage",
            "\"x@bank.example\" <evil@example.net>",
            "a@exa mple.com",
        ] {
            assert!(parse_recipients(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn new_message_has_expected_headers_and_no_bcc_on_the_wire() {
        let mut r = request(Mode::New);
        r.to = "ann@example.com".into();
        r.bcc = "secret@example.org".into();
        r.subject = "Hi\r\nBcc: injected@example.net".into();
        let out = Outgoing::build(&account(), &r, None, vec![]).expect("build");
        assert_eq!(out.recipients(), ["ann@example.com", "secret@example.org"]);
        assert_eq!(out.subject, "Hi Bcc: injected@example.net");

        let wire = text_of(&out.to_bytes(false).expect("bytes"));
        assert!(
            wire.contains("From: \"Me Myself\" <me@example.com>"),
            "{wire}"
        );
        assert!(wire.contains("To: <ann@example.com>"), "{wire}");
        assert!(!wire.to_lowercase().contains("secret@example.org"));
        assert!(!wire.contains("\nBcc:"));
        // The body is quoted-printable, so the signature marker's trailing space is "=20".
        assert!(wire.contains("Hello there\r\n\r\n--=20\r\nMe"), "{wire}");
        assert_eq!(out.own_text, "Hello there\n\n-- \nMe");

        let draft = text_of(&out.to_bytes(true).expect("bytes"));
        assert!(draft.contains("Bcc: <secret@example.org>"), "{draft}");
    }

    #[test]
    fn reply_all_addresses_threads_and_quotes() {
        let original = message::parse(ORIGINAL.as_bytes()).expect("parse");
        let out = Outgoing::build(
            &account(),
            &request(Mode::ReplyAll),
            Some(&original),
            vec![],
        )
        .expect("build");
        assert_eq!(
            out.to
                .iter()
                .map(|m| m.address.as_str())
                .collect::<Vec<_>>(),
            ["ann@example.com"]
        );
        // Own address and own alias are left out; everyone else is copied once.
        assert_eq!(
            out.cc
                .iter()
                .map(|m| m.address.as_str())
                .collect::<Vec<_>>(),
            ["bob@example.org", "carol@example.net"]
        );
        assert_eq!(out.subject, "Re: Lunch");
        assert_eq!(out.in_reply_to.as_deref(), Some("orig@example.com"));
        assert_eq!(out.references, ["first@example.com", "orig@example.com"]);
        let quoted = out.quoted.as_ref().expect("quoted");
        assert!(
            quoted
                .block
                .contains("Ann <ann@example.com> wrote:\n> Shall we?\n> Second line")
        );

        let wire = text_of(&out.to_bytes(false).expect("bytes"));
        assert!(wire.contains("In-Reply-To: <orig@example.com>"), "{wire}");
        assert!(
            wire.contains("References: <first@example.com> <orig@example.com>"),
            "{wire}"
        );
    }

    #[test]
    fn reply_goes_to_reply_to_and_warns_when_it_differs() {
        let raw = "From: Ann <ann@example.com>\r\nReply-To: collect@elsewhere.example\r\nSubject: Re: Lunch\r\nMessage-ID: <o@example.com>\r\n\r\nx\r\n";
        let original = message::parse(raw.as_bytes()).expect("parse");
        let out = Outgoing::build(&account(), &request(Mode::Reply), Some(&original), vec![])
            .expect("build");
        assert_eq!(out.recipients(), ["collect@elsewhere.example"]);
        assert_eq!(out.subject, "Re: Lunch");
        assert!(out.warnings.iter().any(|w| w.starts_with("Reply-To")));
        assert!(
            out.describe("Send this email", &account())
                .contains("WARNING: Reply-To")
        );
    }

    #[test]
    fn forward_carries_the_original_and_its_attachments_on_request() {
        let raw = "From: ann@example.com\r\nTo: me@example.com\r\nSubject: Report\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nSee attached\r\n--b\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"../r.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\nJVBERi0=\r\n--b--\r\n";
        let original = message::parse(raw.as_bytes()).expect("parse");
        let mut r = request(Mode::Forward);
        r.to = "bob@example.org".into();
        r.include_original_attachments = true;
        let out = Outgoing::build(&account(), &r, Some(&original), vec![]).expect("build");
        assert_eq!(out.subject, "Fwd: Report");
        assert_eq!(out.attachments.len(), 1);
        assert_eq!(
            (
                out.attachments[0].name.as_str(),
                out.attachments[0].data.as_slice()
            ),
            ("r.pdf", &b"%PDF-"[..])
        );
        assert!(!out.has_local_attachments());
        assert!(
            out.quoted
                .as_ref()
                .expect("quoted")
                .block
                .starts_with("---------- Forwarded message")
        );
    }

    #[test]
    fn dialog_shows_addresses_local_files_links_and_hides_the_quote() {
        let original = message::parse(ORIGINAL.as_bytes()).expect("parse");
        let mut r = request(Mode::Reply);
        r.body = "See https://evil.example/x and reply".into();
        let file = LocalFile {
            path: "/home/me/Documents/tax.pdf".into(),
            name: "tax.pdf".into(),
            content_type: "application/pdf",
            data: vec![0; 2048],
        };
        let out = Outgoing::build(&account(), &r, Some(&original), vec![file]).expect("build");
        assert!(out.has_local_attachments());
        let dialog = out.describe("Send this email", &account());
        assert!(
            dialog.contains("To: ann@example.com  (shown as \"Ann\")"),
            "{dialog}"
        );
        assert!(
            dialog.contains("tax.pdf (2 KB, from your disk: /home/me/Documents/tax.pdf)"),
            "{dialog}"
        );
        assert!(
            dialog.contains("Links in the text go to: evil.example"),
            "{dialog}"
        );
        assert!(dialog.contains("See https://evil.example/x and reply"));
        assert!(dialog.contains("followed by the original message from Ann <ann@example.com>"));
        assert!(!dialog.contains("Shall we?"));
    }

    #[test]
    fn dialog_text_exposes_padding_and_truncation() {
        let padded = format!(
            "Top\n{}Hidden far below{}tail",
            "\n".repeat(60),
            " ".repeat(300)
        );
        let shown = dialog_text(&padded);
        assert!(shown.contains("[60 blank lines]"), "{shown}");
        assert!(shown.contains("[300 spaces]"), "{shown}");
        let long = dialog_text(&"word ".repeat(5000));
        assert!(long.contains("MORE CHARACTERS NOT SHOWN"));
    }

    #[test]
    fn invisible_characters_never_reach_the_wire() {
        let mut r = request(Mode::New);
        r.to = "ann@example.com".into();
        r.body = "pay\u{200B}ment \u{202E}due".into();
        r.add_signature = false;
        let out = Outgoing::build(&account(), &r, None, vec![]).expect("build");
        assert_eq!(out.own_text, "payment due");
    }

    #[test]
    fn too_many_or_no_recipients_are_refused() {
        let mut r = request(Mode::New);
        assert!(Outgoing::build(&account(), &r, None, vec![]).is_err());
        r.to = (0..51)
            .map(|i| format!("u{i}@example.com"))
            .collect::<Vec<_>>()
            .join(", ");
        assert!(Outgoing::build(&account(), &r, None, vec![]).is_err());
    }

    #[test]
    fn headers_are_rewritten_without_touching_the_body() {
        let raw = b"From: me@example.com\r\nBcc: a@example.com,\r\n\tb@example.com\r\nResent-To: x@example.net\r\nSubject: Hi\r\nDate: old\r\n\r\nBcc: this is body text\r\n";
        let out = rewrite_headers(
            raw,
            |n| {
                matches!(n.to_ascii_lowercase().as_str(), "bcc" | "date")
                    || n.to_ascii_lowercase().starts_with("resent-")
            },
            &[("Date", "new".into())],
        );
        assert_eq!(
            text_of(&out),
            "Date: new\r\nFrom: me@example.com\r\nSubject: Hi\r\n\r\nBcc: this is body text\r\n"
        );
        // Unix line endings and a message with no body.
        let out = rewrite_headers(
            b"Bcc: a@b.c\nSubject: Hi",
            |n| n.eq_ignore_ascii_case("bcc"),
            &[],
        );
        assert_eq!(text_of(&out), "Subject: Hi\r\n\r\n");
    }

    #[test]
    fn draft_is_prepared_with_envelope_from_all_recipient_headers() {
        let raw = "From: me@example.com\r\nTo: ann@example.com\r\nCc: bob@example.org\r\nBcc: secret@example.net\r\nSubject: Plan\r\nDate: Mon, 5 Jan 2026 10:00:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: text/html\r\n\r\n<p>Visible</p><div style=\"display:none\">hidden</div><a href=\"https://t.example/c\">click</a>\r\n";
        let prepared = prepare_draft(&account(), raw.as_bytes(), true).expect("prepare");
        assert_eq!(
            prepared.recipients,
            ["ann@example.com", "bob@example.org", "secret@example.net"]
        );
        let wire = text_of(&prepared.bytes);
        assert!(!wire.contains("secret@example.net"));
        assert!(!wire.contains("5 Jan 2026"));
        assert!(wire.contains("Message-ID: <"));
        assert!(prepared.description.contains("Bcc: secret@example.net"));
        assert!(
            prepared
                .description
                .contains("WARNING: Text hidden from the reader")
        );
        assert!(
            prepared
                .description
                .contains("Links and images go to: t.example")
        );
        assert!(prepared.description.contains("Visible"));
    }

    #[test]
    fn draft_from_someone_else_is_refused() {
        let raw = "From: boss@example.com\r\nTo: ann@example.com\r\nSubject: x\r\n\r\nbody\r\n";
        assert!(prepare_draft(&account(), raw.as_bytes(), true).is_err());
        let alias = "From: me@alias.example\r\nTo: ann@example.com\r\nSubject: x\r\n\r\nbody\r\n";
        assert!(prepare_draft(&account(), alias.as_bytes(), true).is_ok());
        let unmarked = prepare_draft(&account(), alias.as_bytes(), false).expect("prepare");
        assert!(unmarked.description.contains("not marked as a draft"));
    }
}
