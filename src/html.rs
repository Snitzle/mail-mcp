//! Turn an HTML email into the text a person reading it would see.
//!
//! The document is parsed with a real HTML5 parser (the same tree-building rules a browser
//! uses), then walked once. Elements hidden by inline styles, by the `hidden` attribute or
//! by `<style>` rules are dropped. Link destinations are written out next to the link text
//! so a link that says one thing and points somewhere else is visible.
//!
//! This cannot be complete: colour inherited from an ancestor, images of text, and fonts
//! that draw nothing are all out of reach. Callers must still treat the result as
//! untrusted.

use std::collections::HashSet;

use ego_tree::NodeId;
use ego_tree::iter::Edge;
use scraper::{Html, Node, Selector};

use crate::css;
use crate::sanitize::truncate_chars;

const MAX_HTML_BYTES: usize = 2 * 1024 * 1024;
const MAX_URLS: usize = 200;
const MAX_URL_CHARS: usize = 500;
const MAX_HIDING_RULES: usize = 200;
/// Browsers stop nesting at a few hundred levels. Past this we refuse to build a tree at
/// all, because tree building costs time proportional to depth for every tag.
const MAX_NESTING: usize = 1024;

/// Elements whose content is never shown as text.
const SKIPPED: &[&str] = &[
    "script", "style", "head", "title", "template", "noscript", "svg", "object", "iframe", "math",
    "select", "textarea",
];
const BLOCKS: &[&str] = &[
    "p",
    "div",
    "tr",
    "li",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "table",
    "ul",
    "ol",
    "blockquote",
    "section",
    "article",
    "header",
    "footer",
    "pre",
    "dd",
    "dt",
    "figcaption",
    "address",
];
const URL_ATTRIBUTES: &[&str] = &[
    "href",
    "src",
    "background",
    "poster",
    "action",
    "data",
    "srcset",
];

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Extracted {
    /// The visible text.
    pub text: String,
    /// Every URL the email refers to, including ones on hidden elements.
    pub urls: Vec<String>,
    /// Text was dropped because it is hidden from a human reader.
    pub hidden_removed: bool,
    /// The stylesheet hides something through a selector we could not apply, so some of the
    /// text returned may be invisible to a human reader.
    pub unresolved_hiding: bool,
    /// The markup is nested too deeply to process safely; `text` is empty.
    pub too_deep: bool,
}

pub fn extract(html: &str) -> Extracted {
    let html = cap_bytes(html, MAX_HTML_BYTES);
    let mut out = Extracted::default();
    if estimated_nesting(html) > MAX_NESTING {
        out.too_deep = true;
        return out;
    }
    let document = Html::parse_document(html);
    let hidden_by_stylesheet = stylesheet_hidden_nodes(&document, &mut out);

    let mut text = String::new();
    // Nodes that started a hidden subtree and are still open.
    let mut hidden_stack: Vec<NodeId> = Vec::new();
    // Open links: destination and where their text starts in `text`.
    let mut links: Vec<(String, usize)> = Vec::new();

    for edge in document.tree.root().traverse() {
        match edge {
            Edge::Open(node) => match node.value() {
                Node::Text(t) => {
                    if hidden_stack.is_empty() {
                        text.push_str(t);
                    }
                }
                Node::Element(el) => {
                    collect_urls(el, &mut out.urls);
                    let name = el.name();
                    let style = el.attr("style").unwrap_or_default();
                    let never_shown = SKIPPED.contains(&name);
                    let hidden = never_shown
                        || el.attr("hidden").is_some()
                        || css::declarations_hide(style)
                        || hidden_by_stylesheet.contains(&node.id());
                    if hidden {
                        // Only report hiding that removed something a reader was meant to
                        // believe was absent; <script>/<style>/<head> are not "hidden text".
                        if !never_shown && hidden_stack.is_empty() && has_text(node) {
                            out.hidden_removed = true;
                        }
                        hidden_stack.push(node.id());
                        continue;
                    }
                    if !hidden_stack.is_empty() {
                        continue;
                    }
                    match name {
                        "br" => text.push('\n'),
                        "img" => {
                            let alt = el.attr("alt").unwrap_or_default().trim();
                            if !alt.is_empty() {
                                let (alt, _) = truncate_chars(alt, 80);
                                text.push_str(&format!("[image: {alt}]"));
                            }
                        }
                        "a" => {
                            links.push((el.attr("href").unwrap_or_default().to_owned(), text.len()))
                        }
                        _ => {}
                    }
                }
                _ => {}
            },
            Edge::Close(node) => {
                if hidden_stack.last() == Some(&node.id()) {
                    hidden_stack.pop();
                    continue;
                }
                if !hidden_stack.is_empty() {
                    continue;
                }
                let Node::Element(el) = node.value() else {
                    continue;
                };
                let name = el.name();
                if name == "a"
                    && let Some((href, start)) = links.pop()
                {
                    let shown = text.get(start..).unwrap_or_default().to_lowercase();
                    if let Some(destination) = link_destination(&href)
                        && !shown.contains(&destination.to_lowercase())
                    {
                        text.push_str(&format!(" [link→{destination}]"));
                    }
                }
                if matches!(name, "td" | "th") {
                    text.push(' ');
                } else if BLOCKS.contains(&name) {
                    text.push('\n');
                }
            }
        }
    }

    out.text = tidy_whitespace(&text);
    out
}

fn cap_bytes(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// A cheap upper estimate of how deeply the markup nests, without building a tree.
/// Elements that browsers close implicitly (`<p>`, `<li>`, ...) and void elements are not
/// counted, since leaving those unclosed is normal and does not deepen the tree.
fn estimated_nesting(html: &str) -> usize {
    const NOT_COUNTED: &[&str] = &[
        "p", "li", "dt", "dd", "option", "tr", "td", "th", "thead", "tbody", "tfoot", "br", "img",
        "hr", "meta", "link", "input", "area", "base", "col", "embed", "param", "source", "track",
        "wbr",
    ];
    let bytes = html.as_bytes();
    let (mut depth, mut deepest) = (0usize, 0usize);
    let mut i = 0;
    while let Some(offset) = bytes[i..].iter().position(|b| *b == b'<') {
        i += offset + 1;
        let closing = bytes.get(i) == Some(&b'/');
        let start = if closing { i + 1 } else { i };
        let len = bytes[start.min(bytes.len())..]
            .iter()
            .take_while(|b| b.is_ascii_alphanumeric())
            .count();
        if len == 0 {
            continue;
        }
        let name = html[start..start + len].to_ascii_lowercase();
        if NOT_COUNTED.contains(&name.as_str()) {
            continue;
        }
        if closing {
            depth = depth.saturating_sub(1);
        } else {
            depth += 1;
            deepest = deepest.max(depth);
        }
    }
    deepest
}

/// Does this subtree contain any non-whitespace text?
fn has_text(node: ego_tree::NodeRef<'_, Node>) -> bool {
    node.descendants()
        .any(|d| matches!(d.value(), Node::Text(t) if !t.trim().is_empty()))
}

/// Apply every `<style>` rule that hides its targets and return the nodes it matches.
fn stylesheet_hidden_nodes(document: &Html, out: &mut Extracted) -> HashSet<NodeId> {
    let mut hidden = HashSet::new();
    let Ok(style_elements) = Selector::parse("style") else {
        return hidden;
    };
    let mut applied = 0;
    for style in document.select(&style_elements) {
        let sheet: String = style.text().collect();
        for url in css::urls(&sheet) {
            push_url(&mut out.urls, &url);
        }
        for rule in css::parse_stylesheet(&sheet) {
            if !css::declarations_hide(&rule.declarations) {
                continue;
            }
            applied += 1;
            if applied > MAX_HIDING_RULES {
                out.unresolved_hiding = true;
                return hidden;
            }
            match Selector::parse(&rule.selectors) {
                Ok(selector) => hidden.extend(document.select(&selector).map(|el| el.id())),
                Err(_) => out.unresolved_hiding = true,
            }
        }
    }
    hidden
}

fn collect_urls(el: &scraper::node::Element, urls: &mut Vec<String>) {
    for attribute in URL_ATTRIBUTES {
        let Some(value) = el.attr(attribute) else {
            continue;
        };
        if *attribute == "srcset" {
            for candidate in value.split(',') {
                if let Some(url) = candidate.split_whitespace().next() {
                    push_url(urls, url);
                }
            }
        } else {
            push_url(urls, value);
        }
    }
    if let Some(style) = el.attr("style") {
        for url in css::urls(style) {
            push_url(urls, &url);
        }
    }
}

fn push_url(urls: &mut Vec<String>, url: &str) {
    let url = url.trim();
    let lower = url.to_ascii_lowercase();
    if url.is_empty()
        || lower.starts_with('#')
        || lower.starts_with("cid:")
        || lower.starts_with("data:")
    {
        return;
    }
    let (url, _) = truncate_chars(url, MAX_URL_CHARS);
    if urls.len() < MAX_URLS && !urls.iter().any(|u| u == url) {
        urls.push(url.to_owned());
    }
}

/// Where a link really goes: the host for web links, the address for `mailto:`.
pub fn link_destination(href: &str) -> Option<String> {
    let href = href.trim();
    if let Some(rest) = href
        .get(..7)
        .filter(|p| p.eq_ignore_ascii_case("mailto:"))
        .map(|_| &href[7..])
    {
        let address = rest.split('?').next().unwrap_or_default().trim();
        return (!address.is_empty()).then(|| address.to_owned());
    }
    let parsed = url::Url::parse(href).ok()?;
    parsed.host_str().map(str::to_owned)
}

/// Collapse runs of spaces, trim each line, and allow at most one blank line in a row.
fn tidy_whitespace(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut blank_run = 0;
    for line in text.split('\n') {
        let mut flat = String::with_capacity(line.len());
        for word in line
            .split(|c: char| c.is_whitespace() || c == '\u{a0}')
            .filter(|w| !w.is_empty())
        {
            if !flat.is_empty() {
                flat.push(' ');
            }
            flat.push_str(word);
        }
        if flat.is_empty() {
            blank_run += 1;
            if blank_run > 1 || out.is_empty() {
                continue;
            }
        } else {
            blank_run = 0;
        }
        out.push_str(&flat);
        out.push('\n');
    }
    out.trim_end().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_structure_becomes_lines() {
        let e = extract(
            "<html><body><h1>Hello</h1><p>One<br>Two</p><ul><li>a</li><li>b</li></ul></body></html>",
        );
        assert_eq!(e.text, "Hello\nOne\nTwo\na\nb");
        assert!(!e.hidden_removed);
    }

    #[test]
    fn inline_hidden_text_is_dropped_and_reported() {
        let e = extract(
            r#"<p>Visible</p><div style="display:none">SECRET INSTRUCTION</div><span style="font-size:0">tiny</span>"#,
        );
        assert_eq!(e.text, "Visible");
        assert!(e.hidden_removed);
    }

    #[test]
    fn stylesheet_hidden_text_is_dropped() {
        let e = extract(
            r#"<html><head><style>.x{display:none} #y > b {opacity:0}</style></head>
               <body><p>Shown</p><p class="x">hidden by class</p><div id="y"><b>hidden by id</b><i>kept</i></div></body></html>"#,
        );
        assert!(e.text.contains("Shown"));
        assert!(e.text.contains("kept"));
        assert!(!e.text.contains("hidden by"));
        assert!(e.hidden_removed);
        assert!(!e.unresolved_hiding);
    }

    #[test]
    fn nested_content_of_hidden_element_stays_hidden() {
        let e = extract(r#"<div hidden><p>a<span>b</span></p></div><p>c</p>"#);
        assert_eq!(e.text, "c");
    }

    #[test]
    fn unclosed_tags_do_not_leak_hidden_text() {
        // A browser auto-closes these the same way the parser does.
        let e = extract(r#"<p style="display:none">hidden<p>shown"#);
        assert_eq!(e.text, "shown");
    }

    #[test]
    fn scripts_styles_and_comments_are_not_text() {
        let e =
            extract("<style>p{color:red}</style><script>alert(1)</script><!-- note --><p>ok</p>");
        assert_eq!(e.text, "ok");
        assert!(!e.hidden_removed);
    }

    #[test]
    fn link_destination_is_shown_when_text_differs() {
        let e = extract(r#"<a href="https://evil.example/login">Sign in to your bank</a>"#);
        assert_eq!(e.text, "Sign in to your bank [link→evil.example]");
        assert_eq!(e.urls, ["https://evil.example/login"]);
    }

    #[test]
    fn link_destination_is_not_repeated_when_text_shows_it() {
        let e = extract(r#"<a href="https://example.com/a">example.com/a</a>"#);
        assert_eq!(e.text, "example.com/a");
    }

    #[test]
    fn userinfo_trick_shows_real_host() {
        assert_eq!(
            link_destination("https://paypal.com@evil.example/x").as_deref(),
            Some("evil.example")
        );
        assert_eq!(
            link_destination("MAILTO:a@b.example?subject=x").as_deref(),
            Some("a@b.example")
        );
        assert_eq!(link_destination("#top"), None);
    }

    #[test]
    fn urls_on_hidden_elements_are_still_listed() {
        let e = extract(
            r#"<div style="display:none"><img src="https://t.example/pixel.gif"></div><p style="background:url(https://b.example/bg.png)">x</p>"#,
        );
        assert_eq!(
            e.urls,
            ["https://t.example/pixel.gif", "https://b.example/bg.png"]
        );
    }

    #[test]
    fn image_alt_text_is_marked() {
        let e = extract(r#"<img alt="Company logo" src="cid:logo">"#);
        assert_eq!(e.text, "[image: Company logo]");
        assert!(e.urls.is_empty());
    }

    #[test]
    fn moderately_nested_markup_is_handled() {
        let html = format!("{}deep{}", "<div>".repeat(500), "</div>".repeat(500));
        assert_eq!(extract(&html).text, "deep");
    }

    #[test]
    fn absurdly_nested_markup_is_refused() {
        let html = format!(
            "{}deep{}",
            "<div>".repeat(200_000),
            "</div>".repeat(200_000)
        );
        let e = extract(&html);
        assert!(e.too_deep);
        assert!(e.text.is_empty());
    }

    #[test]
    fn many_unclosed_paragraphs_are_not_deep() {
        let html = "<p>line".repeat(5_000);
        let e = extract(&html);
        assert!(!e.too_deep);
        assert_eq!(e.text.lines().count(), 5_000);
    }

    #[test]
    fn empty_hidden_elements_are_not_reported() {
        let e = extract(
            r#"<div style="display:none"></div><img style="display:none" src="https://t.example/p.gif"><p>x</p>"#,
        );
        assert!(!e.hidden_removed);
    }
}
