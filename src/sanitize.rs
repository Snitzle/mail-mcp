//! Hygiene for text that came out of an email. Everything in an email is written by a
//! third party, so before it is shown to the model or to the user we strip the characters
//! that render as nothing (and are used to hide instructions) and flatten anything that is
//! meant to occupy a single line.

/// Characters that take up no space on screen, reorder the text around them, or belong to
/// the Unicode "tag" block. None of them carry meaning a reader would miss.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'
            | '\u{1160}'
            | '\u{17B4}'
            | '\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{E0000}'..='\u{E0FFF}'
    )
}

/// Control characters other than newline and tab.
fn is_stray_control(c: char) -> bool {
    c.is_control() && c != '\n' && c != '\t'
}

/// Text with invisible and control characters removed, plus how many were dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cleaned {
    pub text: String,
    pub removed: usize,
}

/// Remove invisible characters and stray control characters. Line endings become `\n`.
pub fn clean(input: &str) -> Cleaned {
    let mut text = String::with_capacity(input.len());
    let mut removed = 0;
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' {
            // CRLF and bare CR both become a single newline; that is not "hidden" content.
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            text.push('\n');
        } else if is_invisible(c) || is_stray_control(c) {
            removed += 1;
        } else {
            text.push(c);
        }
    }
    Cleaned { text, removed }
}

/// Cut `s` to at most `limit` characters. Returns the text and whether anything was cut.
pub fn truncate_chars(s: &str, limit: usize) -> (&str, bool) {
    match s.char_indices().nth(limit) {
        Some((idx, _)) => (&s[..idx], true),
        None => (s, false),
    }
}

/// For anything shown on a single line (header values, file names, dialog fields): no line
/// breaks, no invisible characters, whitespace collapsed, and a hard length limit.
pub fn oneline(s: &str, limit: usize) -> String {
    let cleaned = clean(s).text;
    let mut out = String::with_capacity(cleaned.len().min(limit + 4));
    for word in cleaned.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    let (cut, truncated) = truncate_chars(&out, limit);
    if truncated { format!("{cut}…") } else { out }
}

/// A file name that is safe to create inside a directory we control: no path separators,
/// no leading dot, only a conservative character set, and a bounded length.
pub fn safe_filename(name: &str) -> String {
    const MAX_BYTES: usize = 180;
    const MAX_EXT_CHARS: usize = 20;

    // Generous limit here: the real bound is applied below, where the extension is kept.
    let flat = oneline(name, 4096);
    // Keep only the last path component, whichever separator the sender used.
    let base = flat.rsplit(['/', '\\']).next().unwrap_or_default();
    let mut safe: String = base
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ' ' | '(' | ')') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = safe.trim().trim_end_matches('.');
    safe = trimmed.to_owned();
    if let Some(rest) = safe.strip_prefix('.') {
        safe = format!("_{rest}");
    }
    if safe.is_empty() {
        return "attachment.bin".to_owned();
    }

    let (stem, ext) = match safe.rfind('.') {
        Some(idx) if idx > 0 => (&safe[..idx], &safe[idx..]),
        _ => (safe.as_str(), ""),
    };
    let (ext, _) = truncate_chars(ext, MAX_EXT_CHARS);
    let mut stem = stem.to_owned();
    while stem.len() + ext.len() > MAX_BYTES {
        stem.pop();
    }
    if stem.is_empty() {
        stem.push_str("attachment");
    }
    format!("{stem}{ext}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_removes_invisible_and_counts() {
        let c = clean("he\u{200B}llo\u{202E} wor\u{E0041}ld\u{0007}");
        assert_eq!(c.text, "hello world");
        assert_eq!(c.removed, 4);
    }

    #[test]
    fn clean_normalises_line_endings_without_counting_them() {
        let c = clean("a\r\nb\rc\n");
        assert_eq!(c.text, "a\nb\nc\n");
        assert_eq!(c.removed, 0);
    }

    #[test]
    fn clean_keeps_ordinary_unicode() {
        let c = clean("Zoë — 日本語 ✓");
        assert_eq!(c.text, "Zoë — 日本語 ✓");
        assert_eq!(c.removed, 0);
    }

    #[test]
    fn oneline_collapses_breaks_and_truncates() {
        assert_eq!(oneline("a\r\n  b\tc", 100), "a b c");
        assert_eq!(oneline("abcdef", 3), "abc…");
        assert_eq!(
            oneline("Subject\nBcc: evil@example.com", 100),
            "Subject Bcc: evil@example.com"
        );
    }

    #[test]
    fn truncate_respects_char_boundaries() {
        assert_eq!(truncate_chars("日本語", 2), ("日本", true));
        assert_eq!(truncate_chars("ab", 2), ("ab", false));
    }

    #[test]
    fn safe_filename_strips_paths_and_dots() {
        assert_eq!(safe_filename("../../etc/passwd"), "passwd");
        assert_eq!(safe_filename("..\\..\\boot.ini"), "boot.ini");
        assert_eq!(safe_filename(".bashrc"), "_bashrc");
        assert_eq!(safe_filename("report (final).pdf"), "report (final).pdf");
        assert_eq!(safe_filename("a\u{202E}fdp.exe"), "afdp.exe");
        assert_eq!(safe_filename("we$ird*name?.txt"), "we_ird_name_.txt");
        assert_eq!(safe_filename(""), "attachment.bin");
        assert_eq!(safe_filename("..."), "attachment.bin");
    }

    #[test]
    fn safe_filename_bounds_length() {
        let long = format!("{}.pdf", "x".repeat(500));
        let safe = safe_filename(&long);
        assert!(safe.len() <= 180);
        assert!(safe.ends_with(".pdf"));
    }
}
