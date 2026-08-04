//! Extraction and resolution of `@file` mentions from agent prompt text.
//!
//! Several agent surfaces let a user reference a file inline with `@path`. The
//! surface inlines the file's content while building the prompt rather than
//! issuing a read tool call, so no tool hook fires for it. To govern that
//! access, a hook adapter re-derives the reads from the prompt: extract the
//! mentions, resolve each to a local file, and read its content for
//! adjudication.
//!
//! This module owns the surface-agnostic pieces of that flow; the adapter
//! decides how to adjudicate what it finds.
//!
//! # Best-effort re-derivation
//!
//! The surface owns the authoritative `@`-parse; this module re-derives it from
//! the prompt text and cannot reproduce it exactly. Known limitations: a
//! mention whose path contains a space is truncated at the space
//! ([`extract_mentions`] stops a body at whitespace), and a prose word that
//! coincidentally names an existing file resolves like a real mention. The
//! parser deliberately errs toward *over*-recognizing mentions (see
//! `is_boundary`) so a governed file is less likely to slip through
//! unadjudicated; a static `Read` deny rule on the surface remains the
//! authoritative hard block.

use std::path::{Component, Path, PathBuf};

/// Characters that commonly trail an `@file` mention in prose but are not part
/// of the path (e.g. `see @src/foo.rs.`). Trimmed from the right, one at a
/// time, when the raw token does not resolve to a file, then re-checked.
const TRAILING_PUNCTUATION: &[char] =
    &['.', ',', ';', ':', '!', '?', ')', ']', '}', '\'', '"', '`'];

/// True when `ch` may immediately precede the `@` of a mention. Start of string
/// is treated as a boundary by [`extract_mentions`].
///
/// The set covers whitespace, opening delimiters, and the separators that glue
/// two mentions together in prose (`,`, `;`, `=`, `>`), so a comma-joined list
/// like `@a.rs,@b.rs` is recognized as two mentions rather than one
/// unresolvable token. It excludes alphanumerics, which keeps embedded `@` such
/// as email addresses (`user@host`) from being read as a mention.
fn is_boundary(ch: char) -> bool {
    ch.is_whitespace()
        || matches!(
            ch,
            '(' | '[' | '{' | '<' | '"' | '\'' | '`' | ',' | ';' | '=' | '>'
        )
}

/// Extract the raw body (the text after `@`) of every `@`-mention in `text`.
///
/// A mention begins at an `@` that starts the string or follows an
/// `is_boundary` character; its body is the run of characters up to the next
/// whitespace or `@` (a following `@` begins a new mention, so glued mentions
/// split correctly). Bodies are returned in order of appearance. Resolution and
/// de-duplication are left to the caller, which has the filesystem context
/// needed to tell a file mention from a directory or an MCP `@server:resource`
/// mention.
#[must_use]
pub fn extract_mentions(text: &str) -> Vec<&str> {
    let mut bodies = Vec::new();
    let mut chars = text.char_indices().peekable();
    let mut prev: Option<char> = None;
    while let Some((idx, ch)) = chars.next() {
        if ch == '@' && prev.is_none_or(is_boundary) {
            let start = idx + '@'.len_utf8();
            let mut end = start;
            while let Some(&(next_idx, next_ch)) = chars.peek() {
                if next_ch.is_whitespace() || next_ch == '@' {
                    break;
                }
                end = next_idx + next_ch.len_utf8();
                prev = Some(next_ch);
                chars.next();
            }
            if end > start {
                bodies.push(&text[start..end]);
            } else {
                // The `@` consumed no body; it is the char preceding whatever
                // comes next.
                prev = Some(ch);
            }
        } else {
            prev = Some(ch);
        }
    }
    bodies
}

/// Resolve every `@`-mention in `prompt` to a distinct existing local file and
/// read its (optional) text content, honoring `cwd` and bounding each read to
/// `max_bytes`.
///
/// This is the high-level entry point most adapters want: it runs the full
/// extract → resolve → de-duplicate → read pass and returns each distinct
/// resolved file once, in first-mention order, paired with its content (`None`
/// when the file is unreadable as UTF-8; see [`read_file_text`]). Directory
/// mentions, MCP `@server:resource` mentions, and dangling paths are skipped.
/// Adapters needing finer control can drive [`extract_mentions`],
/// [`resolve_file`], and [`read_file_text`] directly.
#[must_use]
pub fn resolve_mentioned_files(
    prompt: &str,
    cwd: &str,
    max_bytes: usize,
) -> Vec<(PathBuf, Option<String>)> {
    let mut seen = std::collections::HashSet::new();
    let mut resolved = Vec::new();
    for body in extract_mentions(prompt) {
        let Some(path) = resolve_file(cwd, body) else {
            continue;
        };
        // Return each distinct file once, keyed on the resolved path.
        if !seen.insert(path.clone()) {
            continue;
        }
        let content = read_file_text(&path, max_bytes);
        resolved.push((path, content));
    }
    resolved
}

/// Resolve a mention `body` to an existing regular file, honoring `cwd` for
/// relative paths, and returning the absolute, lexically-normalized path.
///
/// Returns `None` when the body does not name a readable regular file:
/// directory mentions, MCP `@server:resource` mentions, and dangling paths all
/// fall through here. Trailing prose punctuation is trimmed progressively when
/// the raw body does not resolve, so `@src/foo.rs.` still matches `src/foo.rs`.
///
/// The returned path is normalized lexically (`.`/`..` collapsed) but **not**
/// symlink-resolved, so it keeps the same shape a surface's `Read` tool call
/// would carry for the file. Canonicalizing here would diverge from that route
/// (e.g. macOS `/var` → `/private/var`) and let path-keyed policy miss the
/// mention.
#[must_use]
pub fn resolve_file(cwd: &str, body: &str) -> Option<PathBuf> {
    let mut candidate = body;
    loop {
        if let Some(path) = existing_file(cwd, candidate) {
            return Some(path);
        }
        match candidate.char_indices().next_back() {
            Some((idx, ch)) if TRAILING_PUNCTUATION.contains(&ch) => {
                candidate = &candidate[..idx];
            }
            _ => return None,
        }
    }
}

/// Make `rel_or_abs` absolute (relative paths against `cwd`), normalize it
/// lexically, and return it only if it is an existing regular file. `is_file`
/// follows symlinks to the target, so directory mentions are excluded and a
/// symlink to a file is accepted while the returned path stays unresolved.
fn existing_file(cwd: &str, rel_or_abs: &str) -> Option<PathBuf> {
    if rel_or_abs.is_empty() {
        return None;
    }
    let path = Path::new(rel_or_abs);
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        Path::new(cwd).join(path)
    };
    let normalized = lexically_normalize(&absolute);
    normalized.is_file().then_some(normalized)
}

/// Collapse `.` and `..` components without touching the filesystem, leaving
/// symlinks in intermediate components unresolved.
#[must_use]
pub fn lexically_normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

/// Read up to `max_bytes` of `path` as UTF-8 text.
///
/// Returns `None` when the file cannot be opened/read or contains invalid UTF-8
/// (e.g. binary): callers can still adjudicate the mention by path, just
/// without inlined content, mirroring that the surface would not inline it as
/// text either. The read is bounded so a pathologically large file cannot
/// exhaust memory.
///
/// When the byte cap lands in the middle of a multi-byte character, the valid
/// prefix is kept rather than discarding the whole file — otherwise a large
/// UTF-8 file would silently yield no content for content-based policy to scan.
#[must_use]
pub fn read_file_text(path: &Path, max_bytes: usize) -> Option<String> {
    use std::io::Read;
    let mut buf = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(max_bytes as u64)
        .read_to_end(&mut buf)
        .ok()?;
    // Consume `buf` directly so the common valid-UTF-8 path reuses its
    // allocation instead of copying every byte into a fresh `String`.
    match String::from_utf8(buf) {
        Ok(text) => Some(text),
        // `error_len() == None` means the buffer ends in an incomplete
        // multi-byte character — the byte cap cut a valid file mid-codepoint,
        // so keep the valid prefix. Any other error is a genuine invalid byte
        // (binary content) and yields no text.
        Err(err) if err.utf8_error().error_len().is_none() => {
            let valid = err.utf8_error().valid_up_to();
            let mut bytes = err.into_bytes();
            bytes.truncate(valid);
            // Bytes up to `valid_up_to()` are valid UTF-8 by construction.
            String::from_utf8(bytes).ok()
        }
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_mentions_extracts_boundary_prefixed_tokens() {
        assert_eq!(
            extract_mentions("explain @src/a.rs and @b.rs please"),
            vec!["src/a.rs", "b.rs"]
        );
        assert_eq!(extract_mentions("@only.rs"), vec!["only.rs"]);
        // An opening delimiter is a boundary; its trailing `)` is left for the
        // resolver's trailing-punctuation trim to remove.
        assert_eq!(extract_mentions("(@wrapped.rs)"), vec!["wrapped.rs)"]);
    }

    #[test]
    fn extract_mentions_splits_punctuation_glued_mentions() {
        // A comma-joined list must yield both mentions; the trailing `,` on the
        // first body is trimmed later by `resolve_file`.
        assert_eq!(
            extract_mentions("review @a.rs,@b.rs"),
            vec!["a.rs,", "b.rs"]
        );
        assert_eq!(extract_mentions("path=@secret.txt"), vec!["secret.txt"]);
    }

    #[test]
    fn extract_mentions_ignores_embedded_at_like_emails() {
        assert!(extract_mentions("mail me at user@host.com now").is_empty());
        assert!(extract_mentions("no refs here").is_empty());
    }

    #[test]
    fn extract_mentions_surfaces_mcp_resource_token_for_caller_to_reject() {
        // MCP `@server:resource` mentions are surfaced by the parser but fall
        // through filesystem resolution, so the caller skips them.
        assert_eq!(
            extract_mentions("show @github:repos/o/r/issues"),
            vec!["github:repos/o/r/issues"]
        );
    }

    #[test]
    fn resolve_file_resolves_relative_and_trims_trailing_punctuation() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("a.rs"), "fn main() {}").expect("write file");
        let cwd = dir.path().to_string_lossy().into_owned();
        // Lexically normalized, not canonicalized: the expected path keeps the
        // cwd's shape (symlinks unresolved) rather than the canonical target.
        let expected = Path::new(&cwd).join("a.rs");

        assert_eq!(resolve_file(&cwd, "a.rs"), Some(expected.clone()));
        // Trailing prose punctuation is trimmed until the path resolves.
        assert_eq!(resolve_file(&cwd, "a.rs."), Some(expected.clone()));
        assert_eq!(resolve_file(&cwd, "a.rs)."), Some(expected));
    }

    #[test]
    fn resolve_file_collapses_parent_components_without_resolving_symlinks() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("sub")).expect("mkdir");
        std::fs::write(dir.path().join("a.rs"), "fn main() {}").expect("write file");
        let cwd = dir.path().to_string_lossy().into_owned();

        // `sub/../a.rs` normalizes to `<cwd>/a.rs`, no `..` left in the result.
        assert_eq!(
            resolve_file(&cwd, "sub/../a.rs"),
            Some(Path::new(&cwd).join("a.rs"))
        );
    }

    #[test]
    fn resolve_mentioned_files_dedupes_reads_content_and_skips_non_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("a.rs"), "fn a() {}").expect("write a");
        std::fs::write(dir.path().join("b.rs"), "fn b() {}").expect("write b");
        std::fs::create_dir(dir.path().join("sub")).expect("mkdir");
        let cwd = dir.path().to_string_lossy().into_owned();

        // `sub` is a directory (skipped), `missing.rs` is dangling (skipped),
        // and `@a.rs` is mentioned twice (deduped to one entry).
        let resolved = resolve_mentioned_files(
            "see @a.rs and @b.rs and @a.rs and @sub and @missing.rs",
            &cwd,
            1024,
        );

        assert_eq!(
            resolved,
            vec![
                (Path::new(&cwd).join("a.rs"), Some("fn a() {}".to_owned())),
                (Path::new(&cwd).join("b.rs"), Some("fn b() {}".to_owned())),
            ]
        );
    }

    #[test]
    fn resolve_file_rejects_directories_and_missing_paths() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("subdir")).expect("mkdir");
        let cwd = dir.path().to_string_lossy().into_owned();

        assert_eq!(resolve_file(&cwd, "subdir"), None);
        assert_eq!(resolve_file(&cwd, "missing.rs"), None);
        assert_eq!(resolve_file(&cwd, "github:repos/o/r"), None);
    }

    #[test]
    fn read_file_text_reads_utf8_and_bounds_the_read() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("a.txt");
        std::fs::write(&path, "hello world").expect("write file");

        assert_eq!(read_file_text(&path, 1024).as_deref(), Some("hello world"));
        // The read is bounded by `max_bytes`.
        assert_eq!(read_file_text(&path, 5).as_deref(), Some("hello"));
    }

    #[test]
    fn read_file_text_keeps_valid_prefix_when_cap_splits_a_codepoint() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("a.txt");
        // `é` is two bytes (0xC3 0xA9); a 2-byte cap lands mid-character.
        std::fs::write(&path, "aé").expect("write file");

        assert_eq!(read_file_text(&path, 2).as_deref(), Some("a"));
    }

    #[test]
    fn read_file_text_returns_none_for_binary_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bin");
        // A stray 0xFF in the middle is an invalid UTF-8 byte, not a truncated
        // tail, so the whole read is rejected.
        std::fs::write(&path, [0x61u8, 0xFF, 0x62]).expect("write file");

        assert_eq!(read_file_text(&path, 1024), None);
    }

    #[test]
    fn read_file_text_returns_none_for_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(read_file_text(&dir.path().join("missing"), 1024), None);
    }
}
