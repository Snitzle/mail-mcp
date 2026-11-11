//! Just enough CSS to answer one question: does this declaration block, or this stylesheet
//! rule, make an element invisible to someone reading the email?
//!
//! This is deliberately not a CSS engine. There is no cascade and no specificity: a rule
//! that hides an element counts even if a later rule would show it again. Erring that way
//! means the model may miss some text a human can see, which is the safe direction; the
//! reverse (the model reading text a human cannot see) is how hidden instructions work.

/// One `selectors { declarations }` rule that applies when the email is read on a desktop
/// screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub selectors: String,
    pub declarations: String,
}

const MAX_NESTING: u8 = 4;
const MAX_RULES: usize = 2000;

/// Split a stylesheet into its rules, descending into `@media` blocks that apply to a
/// normal desktop screen and skipping every other at-rule.
pub fn parse_stylesheet(css: &str) -> Vec<Rule> {
    let stripped = strip_comments(css);
    let mut rules = Vec::new();
    collect_rules(&stripped, 0, &mut rules);
    rules
}

fn strip_comments(css: &str) -> String {
    let mut out = String::with_capacity(css.len());
    let mut rest = css;
    while let Some(start) = rest.find("/*") {
        out.push_str(&rest[..start]);
        match rest[start + 2..].find("*/") {
            Some(end) => rest = &rest[start + 2 + end + 2..],
            None => return out,
        }
    }
    out.push_str(rest);
    // HTML comment markers are allowed (and ignored) inside <style>.
    out.replace("<!--", " ").replace("-->", " ")
}

fn collect_rules(css: &str, depth: u8, rules: &mut Vec<Rule>) {
    let mut rest = css;
    while rules.len() < MAX_RULES {
        let Some(stop) = rest.find(['{', ';', '}']) else {
            return;
        };
        if !rest[stop..].starts_with('{') {
            // An at-statement such as `@import ...;`, or a stray brace: skip it.
            rest = &rest[stop + 1..];
            continue;
        }
        let prelude = rest[..stop].trim();
        let after = &rest[stop + 1..];
        let Some(end) = matching_brace(after) else {
            return;
        };
        let block = &after[..end];
        rest = &after[end + 1..];

        if let Some(at_rule) = prelude.strip_prefix('@') {
            let lower = at_rule.to_ascii_lowercase();
            let descend = if lower.starts_with("media") {
                media_applies(&lower)
            } else {
                lower.starts_with("supports") || lower.starts_with("layer")
            };
            if descend && depth < MAX_NESTING {
                collect_rules(block, depth + 1, rules);
            }
        } else if !prelude.is_empty() {
            rules.push(Rule {
                selectors: prelude.to_owned(),
                declarations: block.to_owned(),
            });
        }
    }
}

/// Index of the `}` that closes a block whose `{` has already been consumed.
fn matching_brace(s: &str) -> Option<usize> {
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (idx, c) in s.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' => quote = Some(c),
            '{' => depth += 1,
            '}' if depth == 0 => return Some(idx),
            '}' => depth -= 1,
            _ => {}
        }
    }
    None
}

/// Would this `@media` condition (already lower-cased) match a desktop mail reader?
/// Print-only and narrow-screen-only blocks do not; anything else is assumed to.
fn media_applies(prelude: &str) -> bool {
    const DESKTOP_WIDTH_PX: f64 = 800.0;

    let mentions = |word: &str| prelude.contains(word);
    if mentions("print") && !mentions("screen") && !mentions("all") {
        return false;
    }
    if mentions("prefers-color-scheme") && mentions("dark") {
        return false;
    }
    for feature in ["max-width", "max-device-width"] {
        if let Some(pos) = prelude.find(feature) {
            let value = prelude[pos + feature.len()..].trim_start_matches([':', ' ']);
            if let Some((px, unit)) = leading_number(value)
                && (unit.starts_with("px") || unit.is_empty())
                && px < DESKTOP_WIDTH_PX
            {
                return false;
            }
        }
    }
    true
}

/// Does this declaration block (an inline `style` attribute or the body of a stylesheet
/// rule) hide the element it applies to?
pub fn declarations_hide(block: &str) -> bool {
    let mut color: Option<String> = None;
    let mut background: Option<String> = None;

    for (property, value) in declarations(block) {
        if declaration_hides(&property, &value) {
            return true;
        }
        match property.as_str() {
            "color" => color = Some(normalise_colour(&value)),
            "background" | "background-color" => background = Some(normalise_colour(&value)),
            _ => {}
        }
    }
    // Text painted in exactly the colour of its own background.
    matches!((color, background), (Some(c), Some(b)) if c == b)
}

/// `property: value` pairs, lower-cased, with `!important` removed.
fn declarations(block: &str) -> impl Iterator<Item = (String, String)> + '_ {
    split_top_level(block, ';').filter_map(|decl| {
        let (property, value) = decl.split_once(':')?;
        let value = value.to_ascii_lowercase().replace("!important", "");
        Some((
            property.trim().to_ascii_lowercase(),
            value.trim().to_owned(),
        ))
    })
}

/// Split on `separator`, ignoring separators inside parentheses or quotes (as in
/// `url(data:image/png;base64,...)`).
fn split_top_level(s: &str, separator: char) -> impl Iterator<Item = &str> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut start = 0;
    for (idx, c) in s.char_indices() {
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' => quote = Some(c),
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            c if c == separator && depth == 0 => {
                parts.push(&s[start..idx]);
                start = idx + c.len_utf8();
            }
            _ => {}
        }
    }
    parts.push(&s[start..]);
    parts.into_iter()
}

fn declaration_hides(property: &str, value: &str) -> bool {
    let number = leading_number(value);
    let is_zero = matches!(number, Some((n, _)) if n == 0.0);
    match property {
        "display" => value == "none",
        "visibility" => value == "hidden" || value == "collapse",
        "opacity" => is_zero,
        "font-size" => match number {
            Some((n, unit)) => {
                n == 0.0 || (n <= 1.0 && (unit.starts_with("px") || unit.starts_with("pt")))
            }
            None => false,
        },
        "height" | "max-height" | "width" | "max-width" => is_zero,
        "color" => colour_is_transparent(value),
        "mso-hide" => value == "all",
        "left" | "top" | "text-indent" | "margin-left" | "margin-top" => {
            matches!(number, Some((n, _)) if n <= -999.0)
        }
        "clip" => compact(value).starts_with("rect(0"),
        "clip-path" => {
            let v = compact(value);
            v.starts_with("inset(100%") || v.starts_with("inset(50%") || v.starts_with("circle(0")
        }
        "transform" => compact(value).contains("scale(0)"),
        _ => false,
    }
}

fn compact(value: &str) -> String {
    value.chars().filter(|c| !c.is_whitespace()).collect()
}

fn normalise_colour(value: &str) -> String {
    let v = compact(value);
    match v.as_str() {
        "white" | "#fff" | "#ffffff" | "rgb(255,255,255)" => "#ffffff".to_owned(),
        "black" | "#000" | "#000000" | "rgb(0,0,0)" => "#000000".to_owned(),
        _ => v,
    }
}

fn colour_is_transparent(value: &str) -> bool {
    let v = compact(value);
    if v == "transparent" {
        return true;
    }
    // rgba(r,g,b,0) / hsla(h,s,l,0) / the slash form `rgb(r g b / 0)`.
    let Some(inner) = v
        .strip_prefix("rgba(")
        .or_else(|| v.strip_prefix("hsla("))
        .or_else(|| v.strip_prefix("rgb("))
        .or_else(|| v.strip_prefix("hsl("))
        .and_then(|rest| rest.strip_suffix(')'))
    else {
        // #rrggbbaa / #rgba with zero alpha.
        return (v.len() == 9 && v.starts_with('#') && v.ends_with("00"))
            || (v.len() == 5 && v.starts_with('#') && v.ends_with('0'));
    };
    let alpha = if let Some((_, alpha)) = inner.split_once('/') {
        Some(alpha)
    } else {
        let parts: Vec<&str> = inner.split(',').collect();
        (parts.len() == 4).then(|| parts[3])
    };
    matches!(alpha.and_then(leading_number), Some((n, _)) if n == 0.0)
}

/// Parse a leading decimal number, returning it with whatever follows (the unit).
fn leading_number(value: &str) -> Option<(f64, &str)> {
    let value = value.trim_start();
    let end = value
        .char_indices()
        .find(|(idx, c)| {
            !(c.is_ascii_digit() || *c == '.' || (*idx == 0 && (*c == '-' || *c == '+')))
        })
        .map_or(value.len(), |(idx, _)| idx);
    let number: f64 = value[..end].parse().ok()?;
    Some((number, value[end..].trim_start()))
}

/// Every `url(...)` target in a piece of CSS.
pub fn urls(css: &str) -> Vec<String> {
    let mut found = Vec::new();
    let lower = css.to_ascii_lowercase();
    let mut from = 0;
    while let Some(pos) = lower[from..].find("url(") {
        let start = from + pos + 4;
        let Some(len) = css[start..].find(')') else {
            break;
        };
        let target = css[start..start + len]
            .trim()
            .trim_matches(['"', '\''])
            .trim();
        if !target.is_empty() {
            found.push(target.to_owned());
        }
        from = start + len;
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inline_hiding_tricks_are_detected() {
        for style in [
            "display:none",
            "DISPLAY : NONE !important",
            "visibility:hidden",
            "opacity:0",
            "opacity: 0.0",
            "font-size:0",
            "font-size:1px",
            "font-size: 0.5pt",
            "max-height:0;overflow:hidden",
            "width:0px",
            "color:transparent",
            "color: rgba(0, 0, 0, 0)",
            "color: rgb(0 0 0 / 0)",
            "color:#ffffff00",
            "mso-hide:all",
            "position:absolute;left:-9999px",
            "text-indent:-99999em",
            "clip: rect(0 0 0 0)",
            "clip-path: inset(100%)",
            "transform: scale(0)",
            "color:#fff;background-color:white",
            "color: #123456; background: #123456",
        ] {
            assert!(declarations_hide(style), "should hide: {style}");
        }
    }

    #[test]
    fn ordinary_styles_are_not_flagged() {
        for style in [
            "",
            "display:block",
            "color:#333;font-size:14px",
            "opacity:0.8",
            "font-size:1em",
            "font-size:10px",
            "margin-left:-10px",
            "height:40px;width:100%",
            "color:#fff;background-color:#0044cc",
            "background:url(data:image/png;base64,AAAA;display:none)",
            "line-height:0",
        ] {
            assert!(!declarations_hide(style), "should not hide: {style}");
        }
    }

    #[test]
    fn stylesheet_rules_are_split() {
        let rules = parse_stylesheet(
            "/* c */ .a, .b { color: red } @import url(x.css); #c>p{display:none}",
        );
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].selectors, ".a, .b");
        assert_eq!(rules[1].selectors, "#c>p");
        assert!(declarations_hide(&rules[1].declarations));
    }

    #[test]
    fn media_blocks_follow_desktop_reading() {
        let css = "
            @media (max-width: 600px) { .desktop { display: none } }
            @media print { .noprint { display: none } }
            @media screen { .x { display: none } }
            @media screen and (min-width: 400px) { .y { visibility: hidden } }
            @font-face { font-family: a; src: url(a.woff) }
            @keyframes k { from { opacity: 0 } to { opacity: 1 } }
            .z { opacity: 0 }";
        let selectors: Vec<String> = parse_stylesheet(css)
            .into_iter()
            .map(|r| r.selectors)
            .collect();
        assert_eq!(selectors, [".x", ".y", ".z"]);
    }

    #[test]
    fn unbalanced_css_does_not_loop_or_panic() {
        assert!(parse_stylesheet(".a { color: red").is_empty());
        assert!(parse_stylesheet("}}}} .a {{{{").is_empty());
        assert_eq!(
            parse_stylesheet(".a{content:\"}\";color:red} .b{}").len(),
            2
        );
    }

    #[test]
    fn css_urls_are_found() {
        assert_eq!(
            urls("background:url('https://a.example/x.png'); mask: URL( b.svg )"),
            ["https://a.example/x.png", "b.svg"]
        );
    }
}
