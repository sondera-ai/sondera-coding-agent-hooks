//! Content blocks → styled terminal text.
//!
//! Two renderers live here. [`prose_lines`] handles markdown — headings, lists,
//! blockquotes, fenced code, and inline emphasis — because agent prompts and
//! scanner explanations are written in it. [`code_lines`] handles source and
//! shell, highlighted by token class.
//!
//! Syntax color still obeys the design rule: every token class maps onto the
//! existing five-tone palette rather than importing an editor's rainbow. A
//! class is a claim about what a run of characters *is* — a string, a number, a
//! command — which is meaning, not decoration.
//!
//! # Limits
//!
//! Highlighting is per line and stateless, so a multi-line string or a `/* */`
//! block comment is only colored on its opening line. That is a deliberate
//! trade: a stateful lexer for eight languages is a large amount of code to
//! carry for a reading view, and mis-lexing degrades to plain text rather than
//! to wrong text.

use crate::content::{Block, Lang};
use crate::theme::{Theme, Tone};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span, Text};

/// Render a block list into the detail pane's text.
///
/// `width` is the pane's inner width. Prose is wrapped to it here rather than
/// by `Paragraph::wrap`, and code is padded to it so the recessed well reads as
/// a solid band rather than as tinted words. Wrapping here is what lets the
/// caller scroll by an exact line count: with Ratatui doing the wrapping, the
/// number of rendered lines is not knowable before the frame is drawn, and the
/// scroll clamp would either overshoot or cut off the end of a long event.
pub fn render_blocks(theme: &Theme, blocks: &[Block], width: u16) -> Text<'static> {
    let mut lines: Vec<Line<'static>> = Vec::new();

    for block in blocks {
        match block {
            Block::Eyebrow(text) => {
                lines.push(theme.eyebrow(text));
            }
            Block::Field { key, value } => {
                lines.push(theme.field(key, value));
            }
            Block::Prose(text) => {
                lines.extend(prose_lines(theme, text, width));
            }
            Block::Bullet(text) => {
                let mut spans = vec![Span::styled(
                    "  • ",
                    Style::new().fg(theme.tone(Tone::Info)),
                )];
                spans.extend(inline_spans(theme, text));
                lines.extend(wrap_spans(spans, width, 4));
            }
            Block::Code {
                lang,
                caption,
                text,
            } => {
                if let Some(caption) = caption {
                    lines.push(Line::from(vec![
                        Span::styled(caption.to_uppercase(), theme.subtle()),
                        Span::styled(format!("  {}", lang.label()), theme.subtle()),
                    ]));
                }
                lines.extend(code_lines(theme, *lang, text, width));
            }
            Block::Gap => lines.push(Line::default()),
        }
    }

    Text::from(lines)
}

// ============================================================================
// Markdown
// ============================================================================

/// Render markdown text into styled lines.
pub fn prose_lines(theme: &Theme, text: &str, width: u16) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let mut fence: Option<Lang> = None;
    let mut fenced: Vec<String> = Vec::new();

    for raw in text.lines() {
        let trimmed = raw.trim_start();

        // Fenced code. The fence's info string picks the highlighter, and the
        // body is buffered so it renders as one well rather than as N wells.
        if let Some(rest) = trimmed.strip_prefix("```") {
            match fence.take() {
                Some(lang) => {
                    lines.extend(code_lines(theme, lang, &fenced.join("\n"), width));
                    fenced.clear();
                }
                None => fence = Some(Lang::from_tag(rest)),
            }
            continue;
        }
        if fence.is_some() {
            fenced.push(raw.to_string());
            continue;
        }

        if trimmed.is_empty() {
            lines.push(Line::default());
        } else if let Some(heading) = heading(trimmed) {
            lines.push(heading_line(theme, heading.0, heading.1));
        } else if trimmed.starts_with("---") || trimmed.starts_with("***") {
            lines.push(Line::from(Span::styled(
                "─".repeat(width.max(1) as usize),
                Style::new().fg(theme.color(theme.hairline)),
            )));
        } else if let Some(quote) = trimmed.strip_prefix("> ").or(trimmed.strip_prefix(">")) {
            let mut spans = vec![Span::styled("▏ ", Style::new().fg(theme.tone(Tone::Info)))];
            spans.extend(inline_spans(theme, quote));
            lines.extend(wrap_spans(spans, width, 2));
        } else if let Some(item) = bullet(trimmed) {
            let indent = raw.len() - trimmed.len();
            let mut spans = vec![Span::styled(
                format!("{}• ", " ".repeat(indent)),
                Style::new().fg(theme.tone(Tone::Info)),
            )];
            spans.extend(inline_spans(theme, item));
            lines.extend(wrap_spans(spans, width, indent + 2));
        } else if let Some((marker, item)) = ordered(trimmed) {
            let mut spans = vec![Span::styled(format!("{marker} "), theme.metric())];
            spans.extend(inline_spans(theme, item));
            lines.extend(wrap_spans(spans, width, marker.chars().count() + 1));
        } else {
            lines.extend(wrap_spans(inline_spans(theme, raw), width, 0));
        }
    }

    // An unterminated fence still has content worth showing.
    if let Some(lang) = fence
        && !fenced.is_empty()
    {
        lines.extend(code_lines(theme, lang, &fenced.join("\n"), width));
    }

    lines
}

/// Greedily wrap styled spans to `width`, indenting continuation lines by
/// `hanging` so a wrapped list item stays visually attached to its marker.
///
/// Styles survive the break: a wrapped bold run is still bold on the next line.
/// A single word longer than the whole width (a URL, a base64 blob) is hard-cut
/// rather than allowed to overflow the pane.
pub fn wrap_spans(spans: Vec<Span<'static>>, width: u16, hanging: usize) -> Vec<Line<'static>> {
    let width = width as usize;
    if width == 0 {
        return vec![Line::from(spans)];
    }
    let hanging = hanging.min(width.saturating_sub(1));

    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut current: Vec<Span<'static>> = Vec::new();
    let mut used = 0usize;

    let mut break_line = |current: &mut Vec<Span<'static>>, used: &mut usize| {
        lines.push(Line::from(std::mem::take(current)));
        *used = hanging;
        if hanging > 0 {
            current.push(Span::raw(" ".repeat(hanging)));
        }
    };

    for span in spans {
        let style = span.style;
        for token in tokens_keeping_spaces(span.content.as_ref()) {
            let len = token.chars().count();
            let blank = token.chars().all(char::is_whitespace);

            if used + len > width && used > hanging {
                break_line(&mut current, &mut used);
                // The space that forced the break is consumed by it.
                if blank {
                    continue;
                }
            }

            // Still too long on a fresh line: chop it into width-sized pieces.
            if len > width.saturating_sub(used) {
                for chunk in chunks(&token, width.saturating_sub(used).max(1)) {
                    let chunk_len = chunk.chars().count();
                    if used + chunk_len > width && used > 0 {
                        break_line(&mut current, &mut used);
                    }
                    used += chunk_len;
                    current.push(Span::styled(chunk, style));
                }
                continue;
            }

            used += len;
            current.push(Span::styled(token, style));
        }
    }

    if !current.is_empty() || lines.is_empty() {
        lines.push(Line::from(current));
    }
    lines
}

/// Split text into word and whitespace runs, preserving both.
fn tokens_keeping_spaces(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_space: Option<bool> = None;
    for c in text.chars() {
        let space = c.is_whitespace();
        if in_space != Some(space) && !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
        }
        in_space = Some(space);
        current.push(c);
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

/// Split `text` into pieces of at most `size` characters.
fn chunks(text: &str, size: usize) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    chars
        .chunks(size.max(1))
        .map(|chunk| chunk.iter().collect())
        .collect()
}

/// Split an ATX heading into its level and text.
fn heading(line: &str) -> Option<(usize, &str)> {
    let hashes = line.chars().take_while(|c| *c == '#').count();
    if hashes == 0 || hashes > 6 {
        return None;
    }
    let rest = line[hashes..].strip_prefix(' ')?;
    Some((hashes, rest))
}

fn heading_line(theme: &Theme, level: usize, text: &str) -> Line<'static> {
    // Terminals have one type size, so heading rank is carried by weight and
    // color instead: h1/h2 take the brand eyebrow, deeper levels step down to
    // body weight so a document still has visible structure.
    let style = match level {
        1 | 2 => theme.eyebrow_style(),
        3 => theme.body().add_modifier(Modifier::BOLD),
        _ => theme.muted().add_modifier(Modifier::BOLD),
    };
    Line::from(Span::styled(text.to_string(), style))
}

fn bullet(line: &str) -> Option<&str> {
    ["- ", "* ", "+ "]
        .iter()
        .find_map(|marker| line.strip_prefix(marker))
}

/// Split `12. text` into its marker and text.
fn ordered(line: &str) -> Option<(&str, &str)> {
    let digits = line.chars().take_while(char::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    let rest = line[digits..].strip_prefix(". ")?;
    Some((&line[..digits + 1], rest))
}

/// Parse inline markdown — `code`, **bold**, *italic*, `[text](url)` — into spans.
pub fn inline_spans(theme: &Theme, text: &str) -> Vec<Span<'static>> {
    let chars: Vec<char> = text.chars().collect();
    let mut spans = Vec::new();
    let mut plain = String::new();
    let mut i = 0;

    let flush = |plain: &mut String, spans: &mut Vec<Span<'static>>| {
        if !plain.is_empty() {
            spans.push(Span::styled(std::mem::take(plain), theme.body()));
        }
    };

    while i < chars.len() {
        match chars[i] {
            '`' => match delimited(&chars, i, "`") {
                Some((content, next)) => {
                    flush(&mut plain, &mut spans);
                    spans.push(Span::styled(
                        content,
                        Style::new()
                            .fg(theme.tone(Tone::Warn))
                            .bg(theme.color(theme.well)),
                    ));
                    i = next;
                }
                None => {
                    plain.push('`');
                    i += 1;
                }
            },
            '*' if chars.get(i + 1) == Some(&'*') => match delimited(&chars, i, "**") {
                Some((content, next)) => {
                    flush(&mut plain, &mut spans);
                    spans.push(Span::styled(
                        content,
                        theme.body().add_modifier(Modifier::BOLD),
                    ));
                    i = next;
                }
                None => {
                    plain.push('*');
                    i += 1;
                }
            },
            '*' | '_' => {
                let marker = chars[i].to_string();
                match delimited(&chars, i, &marker) {
                    Some((content, next)) => {
                        flush(&mut plain, &mut spans);
                        spans.push(Span::styled(
                            content,
                            theme.body().add_modifier(Modifier::ITALIC),
                        ));
                        i = next;
                    }
                    None => {
                        plain.push(chars[i]);
                        i += 1;
                    }
                }
            }
            // [label](target) renders as the label plus a dimmed target: a
            // terminal cannot hide a URL behind a click, and silently dropping
            // it would lose the only thing that says where the link goes.
            '[' => match link(&chars, i) {
                Some((label, target, next)) => {
                    flush(&mut plain, &mut spans);
                    spans.push(Span::styled(
                        label,
                        theme
                            .body()
                            .fg(theme.tone(Tone::Info))
                            .add_modifier(Modifier::UNDERLINED),
                    ));
                    spans.push(Span::styled(format!(" ({target})"), theme.subtle()));
                    i = next;
                }
                None => {
                    plain.push('[');
                    i += 1;
                }
            },
            other => {
                plain.push(other);
                i += 1;
            }
        }
    }

    flush(&mut plain, &mut spans);
    if spans.is_empty() {
        spans.push(Span::styled(String::new(), theme.body()));
    }
    spans
}

/// Read a run delimited by `marker` starting at `start`, returning its content
/// and the index just past the closing marker. `None` when unclosed, so an
/// unmatched `*` renders literally instead of swallowing the rest of the line.
fn delimited(chars: &[char], start: usize, marker: &str) -> Option<(String, usize)> {
    let marker: Vec<char> = marker.chars().collect();
    let body = start + marker.len();
    let mut i = body;
    while i + marker.len() <= chars.len() {
        if chars[i..i + marker.len()] == marker[..] {
            if i == body {
                return None; // empty run: `` or ** — not emphasis
            }
            return Some((chars[body..i].iter().collect(), i + marker.len()));
        }
        i += 1;
    }
    None
}

/// Read `[label](target)` starting at `start`.
fn link(chars: &[char], start: usize) -> Option<(String, String, usize)> {
    let close = (start + 1..chars.len()).find(|&i| chars[i] == ']')?;
    if chars.get(close + 1) != Some(&'(') {
        return None;
    }
    let end = (close + 2..chars.len()).find(|&i| chars[i] == ')')?;
    Some((
        chars[start + 1..close].iter().collect(),
        chars[close + 2..end].iter().collect(),
        end + 1,
    ))
}

// ============================================================================
// Code
// ============================================================================

/// Token classes the highlighter distinguishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tok {
    Plain,
    Comment,
    Str,
    Num,
    Keyword,
    /// A shell command word or a JSON object key — the thing the line is about.
    Subject,
    Punct,
}

/// Render source text into a recessed, highlighted well.
pub fn code_lines(theme: &Theme, lang: Lang, text: &str, width: u16) -> Vec<Line<'static>> {
    let well = theme.color(theme.well);
    let gutter = Style::new().fg(theme.color(theme.hairline)).bg(well);

    text.lines()
        .map(|raw| {
            let mut spans = vec![Span::styled("▏ ", gutter)];
            let mut used = 2usize;
            for (tok, text) in tokenize(lang, raw) {
                used += text.chars().count();
                spans.push(Span::styled(text, tok_style(theme, tok).bg(well)));
            }
            // Pad to the pane width so the well is a continuous band. Lines
            // wider than the pane simply wrap; nothing is truncated away.
            if let Some(pad) = (width as usize).checked_sub(used).filter(|p| *p > 0) {
                spans.push(Span::styled(" ".repeat(pad), Style::new().bg(well)));
            }
            Line::from(spans)
        })
        .collect()
}

fn tok_style(theme: &Theme, tok: Tok) -> Style {
    match tok {
        Tok::Plain => theme.body(),
        Tok::Comment => theme.subtle().add_modifier(Modifier::ITALIC),
        Tok::Str => Style::new().fg(theme.tone(Tone::Warn)),
        Tok::Num => Style::new().fg(theme.tone(Tone::Rare)),
        Tok::Keyword => Style::new().fg(theme.tone(Tone::Info)),
        Tok::Subject => Style::new()
            .fg(theme.tone(Tone::Allow))
            .add_modifier(Modifier::BOLD),
        Tok::Punct => theme.muted(),
    }
}

/// Whether `lang` treats words as shell-style — flags, paths, and `$vars` are
/// one token rather than several.
const fn shell_like(lang: Lang) -> bool {
    matches!(lang, Lang::Bash)
}

fn line_comment(lang: Lang) -> &'static [&'static str] {
    match lang {
        Lang::Bash | Lang::Python | Lang::Toml | Lang::Yaml => &["#"],
        Lang::Rust | Lang::JavaScript | Lang::Go => &["//"],
        // JSON has no comments, and markdown's `#` is a heading.
        Lang::Json | Lang::Markdown | Lang::Plain => &[],
    }
}

fn keywords(lang: Lang) -> &'static [&'static str] {
    match lang {
        Lang::Bash => &[
            "if", "then", "else", "elif", "fi", "for", "while", "do", "done", "case", "esac",
            "function", "return", "export", "local", "set", "source", "in",
        ],
        Lang::Rust => &[
            "fn", "let", "mut", "pub", "use", "mod", "struct", "enum", "impl", "trait", "match",
            "if", "else", "for", "while", "loop", "return", "self", "Self", "async", "await",
            "const", "static", "where", "crate", "move", "ref", "dyn", "as", "in",
        ],
        Lang::Python => &[
            "def", "class", "return", "import", "from", "if", "elif", "else", "for", "while",
            "try", "except", "finally", "with", "as", "lambda", "yield", "async", "await", "pass",
            "raise", "in", "not", "and", "or", "None", "True", "False", "self",
        ],
        Lang::JavaScript => &[
            "function",
            "const",
            "let",
            "var",
            "return",
            "if",
            "else",
            "for",
            "while",
            "class",
            "extends",
            "import",
            "export",
            "from",
            "async",
            "await",
            "new",
            "this",
            "try",
            "catch",
            "finally",
            "throw",
            "typeof",
            "interface",
            "type",
            "null",
            "undefined",
            "true",
            "false",
        ],
        Lang::Go => &[
            "func",
            "package",
            "import",
            "var",
            "const",
            "type",
            "struct",
            "interface",
            "return",
            "if",
            "else",
            "for",
            "range",
            "go",
            "defer",
            "chan",
            "select",
            "switch",
            "case",
            "map",
            "nil",
            "true",
            "false",
        ],
        Lang::Json => &["true", "false", "null"],
        Lang::Toml | Lang::Yaml => &["true", "false", "null"],
        Lang::Markdown | Lang::Plain => &[],
    }
}

/// Split one line into classified tokens.
fn tokenize(lang: Lang, line: &str) -> Vec<(Tok, String)> {
    let chars: Vec<char> = line.chars().collect();
    let mut out: Vec<(Tok, String)> = Vec::new();
    let mut i = 0;
    // Shell only: whether the next word sits where a command goes.
    let mut command_position = shell_like(lang);

    while i < chars.len() {
        let c = chars[i];

        if c.is_whitespace() {
            let start = i;
            while i < chars.len() && chars[i].is_whitespace() {
                i += 1;
            }
            out.push((Tok::Plain, chars[start..i].iter().collect()));
            continue;
        }

        if let Some(marker) = line_comment(lang)
            .iter()
            .find(|marker| starts_with(&chars, i, marker))
        {
            let _ = marker;
            out.push((Tok::Comment, chars[i..].iter().collect()));
            break;
        }

        if c == '"' || c == '\'' || (c == '`' && shell_like(lang)) {
            let start = i;
            i += 1;
            while i < chars.len() {
                // A backslash escapes the next character, so `"a\"b"` is one
                // string rather than two.
                if chars[i] == '\\' {
                    i += 2;
                    continue;
                }
                if chars[i] == c {
                    i += 1;
                    break;
                }
                i += 1;
            }
            let end = i.min(chars.len());
            out.push((Tok::Str, chars[start..end].iter().collect()));
            command_position = false;
            continue;
        }

        if c.is_ascii_digit() {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '.') {
                i += 1;
            }
            out.push((Tok::Num, chars[start..i].iter().collect()));
            command_position = false;
            continue;
        }

        if is_word_char(lang, c) {
            let start = i;
            while i < chars.len() && is_word_char(lang, chars[i]) {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();
            let tok = classify_word(lang, &word, command_position);
            command_position = false;
            out.push((tok, word));
            continue;
        }

        // Punctuation. In a shell, a pipe or separator reopens command
        // position, which is what makes `git log | grep foo` highlight `grep`.
        if shell_like(lang) && matches!(c, '|' | ';' | '&' | '(') {
            command_position = true;
        }
        out.push((Tok::Punct, c.to_string()));
        i += 1;
    }

    if lang == Lang::Json {
        mark_json_keys(&mut out);
    }
    out
}

fn starts_with(chars: &[char], at: usize, marker: &str) -> bool {
    let marker: Vec<char> = marker.chars().collect();
    at + marker.len() <= chars.len() && chars[at..at + marker.len()] == marker[..]
}

fn is_word_char(lang: Lang, c: char) -> bool {
    if c.is_alphanumeric() || c == '_' {
        return true;
    }
    // Shell words absorb the characters that make a flag or a path one thing:
    // `-rf` and `/tmp/x` must not shatter into punctuation.
    shell_like(lang) && matches!(c, '-' | '.' | '/' | '$' | '~' | '*')
}

fn classify_word(lang: Lang, word: &str, command_position: bool) -> Tok {
    if keywords(lang).contains(&word) {
        return Tok::Keyword;
    }
    if shell_like(lang) {
        if word.starts_with('-') {
            return Tok::Punct; // a flag is chrome, not content
        }
        if command_position {
            return Tok::Subject;
        }
    }
    Tok::Plain
}

/// Re-classify JSON strings that are object keys.
///
/// A key is a string whose next non-whitespace token is `:`. Marking it makes
/// a pretty-printed payload scannable by field name.
fn mark_json_keys(tokens: &mut [(Tok, String)]) {
    for i in 0..tokens.len() {
        if tokens[i].0 != Tok::Str {
            continue;
        }
        let is_key = tokens[i + 1..]
            .iter()
            .find(|(tok, text)| !(*tok == Tok::Plain && text.trim().is_empty()))
            .is_some_and(|(tok, text)| *tok == Tok::Punct && text == ":");
        if is_key {
            tokens[i].0 = Tok::Subject;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::Depth;

    fn theme() -> Theme {
        Theme::dark(Depth::TrueColor)
    }

    /// Flatten a line back to its text, so tests assert on content without
    /// depending on how spans happen to be split.
    fn text_of(line: &Line<'_>) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    fn kinds(lang: Lang, line: &str) -> Vec<(Tok, String)> {
        tokenize(lang, line)
            .into_iter()
            .filter(|(tok, text)| !(*tok == Tok::Plain && text.trim().is_empty()))
            .collect()
    }

    #[test]
    fn a_shell_command_word_is_the_subject() {
        let tokens = kinds(Lang::Bash, "rm -rf /tmp/x");
        assert_eq!(tokens[0], (Tok::Subject, "rm".to_string()));
        assert_eq!(tokens[1], (Tok::Punct, "-rf".to_string()));
        assert_eq!(tokens[2], (Tok::Plain, "/tmp/x".to_string()));
    }

    #[test]
    fn a_pipe_reopens_shell_command_position() {
        let tokens = kinds(Lang::Bash, "git log | grep foo");
        assert!(tokens.contains(&(Tok::Subject, "git".to_string())));
        assert!(tokens.contains(&(Tok::Subject, "grep".to_string())));
        assert!(tokens.contains(&(Tok::Plain, "foo".to_string())));
    }

    #[test]
    fn an_escaped_quote_does_not_end_a_string() {
        let tokens = kinds(Lang::Bash, r#"echo "a\"b" tail"#);
        assert!(tokens.contains(&(Tok::Str, r#""a\"b""#.to_string())));
        // `tail` lands after the string, so the string closed where it should.
        assert!(tokens.contains(&(Tok::Plain, "tail".to_string())));
    }

    #[test]
    fn a_comment_runs_to_end_of_line() {
        let tokens = kinds(Lang::Rust, "let x = 1; // set x");
        assert_eq!(tokens.last().unwrap().0, Tok::Comment);
        assert_eq!(tokens.last().unwrap().1, "// set x");
    }

    #[test]
    fn json_object_keys_are_distinguished_from_string_values() {
        let tokens = kinds(Lang::Json, r#"{"tool": "Bash"}"#);
        assert!(tokens.contains(&(Tok::Subject, "\"tool\"".to_string())));
        assert!(tokens.contains(&(Tok::Str, "\"Bash\"".to_string())));
    }

    #[test]
    fn json_has_no_comment_syntax() {
        let tokens = kinds(Lang::Json, r##"{"a": "#b"}"##);
        assert!(!tokens.iter().any(|(tok, _)| *tok == Tok::Comment));
    }

    #[test]
    fn code_lines_pad_to_the_pane_width() {
        let lines = code_lines(&theme(), Lang::Bash, "ls", 20);
        assert_eq!(text_of(&lines[0]).chars().count(), 20);
    }

    #[test]
    fn a_long_code_line_is_never_truncated() {
        let long = "x".repeat(200);
        let lines = code_lines(&theme(), Lang::Plain, &long, 20);
        assert!(text_of(&lines[0]).contains(&long));
    }

    #[test]
    fn fenced_code_inside_prose_is_highlighted_as_its_language() {
        let lines = prose_lines(&theme(), "intro\n```bash\nrm -rf /\n```\nafter", 40);
        // The fence markers themselves never render.
        assert!(!lines.iter().any(|l| text_of(l).contains("```")));
        assert!(lines.iter().any(|l| text_of(l).contains("rm -rf /")));
        assert!(lines.iter().any(|l| text_of(l).trim() == "after"));
    }

    #[test]
    fn an_unterminated_fence_still_shows_its_content() {
        let lines = prose_lines(&theme(), "```rust\nfn main() {}", 40);
        assert!(lines.iter().any(|l| text_of(l).contains("fn main() {}")));
    }

    #[test]
    fn headings_lose_their_hashes_but_keep_their_text() {
        let lines = prose_lines(&theme(), "## Findings", 40);
        assert_eq!(text_of(&lines[0]), "Findings");
    }

    #[test]
    fn bullets_and_ordered_items_get_markers() {
        let lines = prose_lines(&theme(), "- one\n2. two", 40);
        assert!(text_of(&lines[0]).starts_with("• "));
        assert!(text_of(&lines[1]).starts_with("2. "));
    }

    #[test]
    fn inline_emphasis_drops_its_delimiters() {
        let spans = inline_spans(&theme(), "a **b** and `c`");
        let text: String = spans.iter().map(|s| s.content.as_ref()).collect::<String>();
        assert_eq!(text, "a b and c");
    }

    #[test]
    fn an_unmatched_delimiter_renders_literally() {
        let spans = inline_spans(&theme(), "2 * 3 is 6");
        let text: String = spans.iter().map(|s| s.content.as_ref()).collect::<String>();
        assert_eq!(text, "2 * 3 is 6");
    }

    #[test]
    fn a_link_keeps_both_its_label_and_its_target() {
        let spans = inline_spans(&theme(), "see [docs](https://x.dev)");
        let text: String = spans.iter().map(|s| s.content.as_ref()).collect::<String>();
        assert_eq!(text, "see docs (https://x.dev)");
    }

    #[test]
    fn empty_emphasis_is_not_treated_as_emphasis() {
        let spans = inline_spans(&theme(), "a ** b");
        let text: String = spans.iter().map(|s| s.content.as_ref()).collect::<String>();
        assert_eq!(text, "a ** b");
    }

    #[test]
    fn prose_wraps_at_the_pane_width() {
        let lines = prose_lines(&theme(), "alpha beta gamma delta epsilon", 12);
        assert!(lines.len() > 1);
        assert!(lines.iter().all(|l| text_of(l).chars().count() <= 12));
    }

    #[test]
    fn a_wrapped_bullet_indents_its_continuation() {
        let lines = prose_lines(&theme(), "- alpha beta gamma delta", 12);
        assert!(lines.len() > 1);
        assert!(text_of(&lines[0]).starts_with("• "));
        assert!(text_of(&lines[1]).starts_with("  "));
    }

    #[test]
    fn a_word_longer_than_the_pane_is_hard_cut_not_overflowed() {
        let lines = prose_lines(&theme(), &"x".repeat(50), 10);
        assert!(lines.iter().all(|l| text_of(l).chars().count() <= 10));
        let joined: String = lines.iter().map(|l| text_of(l)).collect();
        assert_eq!(joined.matches('x').count(), 50);
    }

    #[test]
    fn wrapping_preserves_span_styles_across_the_break() {
        let lines = prose_lines(&theme(), "**alpha beta gamma delta**", 12);
        assert!(lines.len() > 1);
        assert!(
            lines
                .iter()
                .flat_map(|l| l.spans.iter())
                .filter(|s| !s.content.trim().is_empty())
                .all(|s| s.style.add_modifier.contains(Modifier::BOLD))
        );
    }

    #[test]
    fn a_zero_width_pane_does_not_hang_or_panic() {
        let lines = prose_lines(&theme(), "alpha beta", 0);
        assert_eq!(lines.len(), 1);
    }

    #[test]
    fn render_blocks_emits_every_block_kind() {
        let blocks = vec![
            Block::Eyebrow("action".into()),
            Block::Field {
                key: "tool".into(),
                value: "Bash".into(),
            },
            Block::Gap,
            Block::Prose("does **things**".into()),
            Block::Bullet("a note".into()),
            Block::Code {
                lang: Lang::Bash,
                caption: Some("command".into()),
                text: "ls -la".into(),
            },
        ];
        let text = render_blocks(&theme(), &blocks, 40);
        let rendered: Vec<String> = text.lines.iter().map(text_of).collect();
        assert!(rendered.iter().any(|l| l == "ACTION"));
        assert!(rendered.iter().any(|l| l.starts_with("tool")));
        assert!(rendered.iter().any(|l| l.contains("does things")));
        assert!(rendered.iter().any(|l| l.contains("• a note")));
        assert!(rendered.iter().any(|l| l.contains("COMMAND")));
        assert!(rendered.iter().any(|l| l.contains("ls -la")));
    }
}
