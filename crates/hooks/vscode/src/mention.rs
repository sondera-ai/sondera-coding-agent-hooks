//! Resolution of `@`-mentioned files in a VS Code Copilot Chat prompt.
//!
//! Copilot Chat inlines a mentioned file's content while it assembles the
//! prompt instead of issuing a read tool call, so no `PreToolUse` hook fires
//! and neither path- nor content-keyed policy ever sees the access.
//! [`crate::hooks`] re-derives those reads over [`sondera_hooks::mention`], the
//! way the Claude adapter does. This module adapts the shared, surface-agnostic
//! extractor to the two things about VS Code's syntax it cannot know:
//!
//! 1. **The body carries a chat-variable scheme.** A file picked in the UI
//!    reaches the hook as `@file:authorized_keys`, so the leading `file:` comes
//!    off before the body names anything on disk.
//! 2. **What follows the scheme is a rendered label, not a path.** VS Code
//!    shows the basename and keeps the directory in the editor's URI, which
//!    never reaches the hook payload — the payload for the
//!    `.ssh/authorized_keys` read that motivated this module was the literal
//!    string `read @file:authorized_keys`. A body with no separator is
//!    therefore located by searching the workspace under `cwd`.
//!
//! # Best-effort, like the shared extractor
//!
//! The basename search matches against the filesystem rather than against the
//! URI the user actually picked, so a label naming more than one file in the
//! workspace resolves to all of them. The payload does not carry enough to
//! disambiguate, and adjudicating every candidate is the side to err on: a
//! missed one is an ungoverned read of exactly the kind this module exists to
//! close. It is not free — a policy denying any candidate blocks the whole
//! prompt — which is why the search runs only for a label that resolves to
//! nothing directly, and a direct hit shadows same-named files deeper in the
//! tree rather than adding to them.
//!
//! Two mention spellings stay out of reach here. `#file:` is VS Code's other
//! variable prefix, and [`sondera_hooks::mention::extract_mentions`] only
//! recognizes `@`; and a mention whose label contains a space is truncated at
//! the space by that same extractor.

use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};

use sondera_hooks::mention as shared;

/// Chat-variable scheme VS Code prefixes onto a file mention.
const FILE_SCHEME: &str = "file:";

/// Directory names the basename search never descends into. Large, generated,
/// and never what a user picks in the file widget. Dot-directories are *not*
/// skipped as a class: `.ssh`, `.github`, and `.aws` are exactly where the
/// files worth governing sit.
const SKIPPED_DIRS: &[&str] = &[".git", "node_modules", "target"];

/// Upper bound on directory entries visited by one basename search, so a prompt
/// submitted in a huge tree cannot stall the hook against its wall-clock budget.
const MAX_SEARCH_ENTRIES: usize = 20_000;

/// Upper bound on directory depth descended by one basename search.
const MAX_SEARCH_DEPTH: usize = 12;

/// Upper bound on same-named files adjudicated for one bare-label mention.
const MAX_SEARCH_MATCHES: usize = 8;

/// Resolve every `@`-mention in `prompt` to distinct existing local files and
/// read each one's (optional) text content, honoring `cwd` and bounding every
/// read to `max_bytes`.
///
/// Returns each distinct resolved file once, in first-mention order, paired
/// with its content (`None` when the file is unreadable as UTF-8; see
/// [`sondera_hooks::mention::read_file_text`]). Directory mentions, chat
/// participants such as `@workspace`, MCP `@server:resource` mentions, and
/// dangling paths resolve to nothing and are dropped.
///
/// One mention can yield several files: a bare label that names more than one
/// file in the workspace resolves to all of them, up to an internal cap.
#[must_use]
pub fn resolve_prompt_mentions(
    prompt: &str,
    cwd: &str,
    max_bytes: usize,
) -> Vec<(PathBuf, Option<String>)> {
    let mut seen = HashSet::new();
    let mut resolved = Vec::new();
    for body in shared::extract_mentions(prompt) {
        for path in resolve_body(cwd, body) {
            // Return each distinct file once, keyed on the resolved path.
            if !seen.insert(path.clone()) {
                continue;
            }
            let content = shared::read_file_text(&path, max_bytes);
            resolved.push((path, content));
        }
    }
    resolved
}

/// Resolve one mention body to zero or more existing files.
///
/// A body that names a path resolves through the shared resolver, which already
/// handles `cwd`, lexical `..` collapse, and trailing prose punctuation. Only a
/// bare label — no separator, and nothing on disk at that name under `cwd` —
/// falls through to the workspace search.
///
/// A direct hit therefore shadows same-named files deeper in the tree: a
/// mention of `authorized_keys` in a workspace that has one at its root
/// adjudicates that one and does not also go looking for `.ssh/authorized_keys`.
/// Searching in both cases would adjudicate files the user never mentioned, and
/// a spurious match blocks the whole prompt rather than costing one extra check
/// — the search is a fallback for a label that resolves to nothing, not a
/// second opinion on one that resolves.
fn resolve_body(cwd: &str, body: &str) -> Vec<PathBuf> {
    let body = strip_file_scheme(body);
    if let Some(path) = shared::resolve_file(cwd, body) {
        return vec![path];
    }
    // A body with a separator is a path that did not resolve, not a label to
    // search for; searching on its last component would silently widen a
    // mention the user wrote as a specific path.
    if body.contains('/') || body.contains('\\') {
        return Vec::new();
    }
    let candidates = label_candidates(body);
    if candidates.is_empty() {
        return Vec::new();
    }
    find_by_basename(Path::new(cwd), &candidates)
}

/// Strip VS Code's `file:` chat-variable scheme from a mention body.
///
/// `str::get` returns `None` rather than panicking when the scheme's length
/// lands inside a multi-byte character, so a mention body that starts with
/// non-ASCII text falls through unchanged.
fn strip_file_scheme(body: &str) -> &str {
    match body.get(..FILE_SCHEME.len()) {
        Some(prefix) if prefix.eq_ignore_ascii_case(FILE_SCHEME) => &body[FILE_SCHEME.len()..],
        _ => body,
    }
}

/// Build the label spellings to search for, trimming trailing non-alphanumeric
/// characters one at a time so a mention written in prose (`@file:notes.md.`)
/// still matches the file on disk.
///
/// The shared resolver does the equivalent trim against the filesystem, one
/// candidate per `stat`. Here the candidates are enumerated up front instead,
/// so the workspace is walked once for all of them rather than once each.
fn label_candidates(label: &str) -> Vec<&str> {
    if label.is_empty() {
        return Vec::new();
    }
    let mut candidates = vec![label];
    let mut current = label;
    while let Some((idx, ch)) = current.char_indices().next_back() {
        if ch.is_alphanumeric() {
            break;
        }
        current = &current[..idx];
        if current.is_empty() {
            break;
        }
        candidates.push(current);
    }
    candidates
}

/// Breadth-first search under `root` for regular files whose name is one of
/// `candidates`, bounded by entries visited, depth, and matches returned.
///
/// Returns lexically-normalized paths, keeping the shape a `read_file` tool
/// call would have carried — canonicalizing here would diverge from that route
/// (macOS `/var` → `/private/var`) and let path-keyed policy miss the mention.
fn find_by_basename(root: &Path, candidates: &[&str]) -> Vec<PathBuf> {
    let mut matches = Vec::new();
    let mut queue = VecDeque::from([(root.to_path_buf(), 0usize)]);
    let mut visited = 0usize;

    while let Some((dir, depth)) = queue.pop_front() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            visited += 1;
            if visited > MAX_SEARCH_ENTRIES {
                return matches;
            }
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name();

            if file_type.is_dir() {
                // `file_type` does not follow symlinks, so a symlinked
                // directory is never descended into and no cycle can form. A
                // directory whose name is not UTF-8 is still descended into:
                // only the filename comparison below needs UTF-8, and skipping
                // the directory outright would hide every file beneath it.
                if depth < MAX_SEARCH_DEPTH
                    && !name
                        .to_str()
                        .is_some_and(|name| SKIPPED_DIRS.contains(&name))
                {
                    queue.push_back((entry.path(), depth + 1));
                }
                continue;
            }

            let Some(name) = name.to_str() else {
                continue;
            };
            if !candidates.contains(&name) {
                continue;
            }
            let path = entry.path();
            // `is_file` follows symlinks, so a symlink to a regular file is
            // kept while a fifo or socket sharing the name is not — opening one
            // would block the hook until something wrote to it.
            if path.is_file() {
                matches.push(shared::lexically_normalize(&path));
                if matches.len() >= MAX_SEARCH_MATCHES {
                    return matches;
                }
            }
        }
    }
    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_file_scheme_removes_the_chat_variable_prefix() {
        assert_eq!(strip_file_scheme("file:authorized_keys"), "authorized_keys");
        assert_eq!(strip_file_scheme("FILE:a.rs"), "a.rs");
        assert_eq!(strip_file_scheme("src/a.rs"), "src/a.rs");
        // A body shorter than the scheme, and one whose first characters are
        // multi-byte, both fall through rather than panicking on a slice.
        assert_eq!(strip_file_scheme("a.rs"), "a.rs");
        assert_eq!(strip_file_scheme("héllo"), "héllo");
    }

    #[test]
    fn label_candidates_trims_trailing_punctuation_progressively() {
        assert_eq!(label_candidates("authorized_keys"), vec!["authorized_keys"]);
        assert_eq!(label_candidates("notes.md."), vec!["notes.md.", "notes.md"]);
        assert_eq!(label_candidates("a.rs)."), vec!["a.rs).", "a.rs)", "a.rs"]);
        assert!(label_candidates("").is_empty());
    }

    #[test]
    fn resolves_a_bare_label_to_a_file_in_a_nested_dot_directory() {
        // The motivating case: VS Code renders `@file:authorized_keys` for a
        // file the payload never spells out as `.ssh/authorized_keys`.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join(".ssh")).expect("mkdir .ssh");
        std::fs::write(dir.path().join(".ssh/authorized_keys"), "ssh-ed25519 AAAA")
            .expect("write file");
        let cwd = dir.path().to_string_lossy().into_owned();

        let resolved = resolve_prompt_mentions("read @file:authorized_keys ", &cwd, 1024);

        assert_eq!(
            resolved,
            vec![(
                dir.path().join(".ssh/authorized_keys"),
                Some("ssh-ed25519 AAAA".to_owned())
            )]
        );
    }

    #[test]
    fn a_body_that_names_a_path_resolves_without_searching() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("src")).expect("mkdir");
        std::fs::write(dir.path().join("src/a.rs"), "fn a() {}").expect("write file");
        let cwd = dir.path().to_string_lossy().into_owned();

        assert_eq!(
            resolve_prompt_mentions("see @file:src/a.rs", &cwd, 1024),
            vec![(dir.path().join("src/a.rs"), Some("fn a() {}".to_owned()))]
        );
        // Bare `@path` (no scheme) still resolves, matching the Claude surface.
        assert_eq!(
            resolve_prompt_mentions("see @src/a.rs", &cwd, 1024),
            vec![(dir.path().join("src/a.rs"), Some("fn a() {}".to_owned()))]
        );
    }

    #[test]
    fn an_unresolvable_path_body_is_not_widened_into_a_basename_search() {
        // `missing/a.rs` does not exist; searching for `a.rs` anywhere would
        // adjudicate a file the user did not mention.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("src")).expect("mkdir");
        std::fs::write(dir.path().join("src/a.rs"), "fn a() {}").expect("write file");
        let cwd = dir.path().to_string_lossy().into_owned();

        assert!(resolve_prompt_mentions("see @file:missing/a.rs", &cwd, 1024).is_empty());
    }

    #[test]
    fn an_ambiguous_label_resolves_to_every_match() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("a")).expect("mkdir a");
        std::fs::create_dir(dir.path().join("b")).expect("mkdir b");
        std::fs::write(dir.path().join("a/creds"), "one").expect("write a");
        std::fs::write(dir.path().join("b/creds"), "two").expect("write b");
        let cwd = dir.path().to_string_lossy().into_owned();

        let resolved = resolve_prompt_mentions("read @file:creds", &cwd, 1024);

        assert_eq!(resolved.len(), 2, "both candidates must be adjudicated");
        let paths: HashSet<_> = resolved.into_iter().map(|(path, _)| path).collect();
        assert_eq!(
            paths,
            HashSet::from([dir.path().join("a/creds"), dir.path().join("b/creds")])
        );
    }

    #[test]
    fn the_search_skips_generated_directories() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("node_modules")).expect("mkdir");
        std::fs::write(dir.path().join("node_modules/creds"), "vendored").expect("write file");
        let cwd = dir.path().to_string_lossy().into_owned();

        assert!(resolve_prompt_mentions("read @file:creds", &cwd, 1024).is_empty());
    }

    #[test]
    fn the_skip_list_matches_a_directory_name_exactly() {
        // `target-old` merely starts with a skipped name; skipping it would
        // hide files a prefix match was never meant to cover.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("target-old")).expect("mkdir");
        std::fs::write(dir.path().join("target-old/creds"), "kept").expect("write file");
        let cwd = dir.path().to_string_lossy().into_owned();

        assert_eq!(
            resolve_prompt_mentions("read @file:creds", &cwd, 1024),
            vec![(dir.path().join("target-old/creds"), Some("kept".to_owned()))]
        );
    }

    #[test]
    fn a_direct_hit_shadows_same_named_files_deeper_in_the_tree() {
        // Documented behavior, pinned: the search is a fallback for a label
        // that resolves to nothing, not a second opinion on one that resolves.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join(".ssh")).expect("mkdir .ssh");
        std::fs::write(dir.path().join("authorized_keys"), "root copy").expect("write root");
        std::fs::write(dir.path().join(".ssh/authorized_keys"), "ssh copy").expect("write ssh");
        let cwd = dir.path().to_string_lossy().into_owned();

        assert_eq!(
            resolve_prompt_mentions("read @file:authorized_keys", &cwd, 1024),
            vec![(
                dir.path().join("authorized_keys"),
                Some("root copy".to_owned())
            )]
        );
    }

    #[test]
    fn distinct_files_are_deduped_across_mentions() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("a.rs"), "fn a() {}").expect("write file");
        let cwd = dir.path().to_string_lossy().into_owned();

        // The same file named twice, once by path and once by bare label.
        let resolved = resolve_prompt_mentions("@file:a.rs and @file:a.rs", &cwd, 1024);

        assert_eq!(resolved.len(), 1);
    }

    #[test]
    fn participants_directories_and_dangling_mentions_resolve_to_nothing() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("subdir")).expect("mkdir");
        let cwd = dir.path().to_string_lossy().into_owned();

        assert!(
            resolve_prompt_mentions(
                "@workspace @terminal @subdir @file:missing.rs @github:repos/o/r",
                &cwd,
                1024
            )
            .is_empty()
        );
    }
}
