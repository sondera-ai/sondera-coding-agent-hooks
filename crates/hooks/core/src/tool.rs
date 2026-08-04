//! Tool-name and tool-argument normalization shared by the hook adapters.
//!
//! Every host agent names the same handful of primitives differently, and a
//! single agent renames them between versions — VS Code Copilot has shipped
//! both `readFile` and `read_file` for the same call. An adapter that matches
//! the literal string silently demotes an unrecognized name to a generic
//! `ToolCall`, which `crates/policy/cedar` maps to
//! `Sondera::Action::"PreToolUse"`. No file, shell, or web policy applies to
//! that action, so the call is recorded and allowed rather than adjudicated
//! against the rules written for it. The failure is invisible: the trajectory
//! shows a clean `Allow` from the default permit.
//!
//! Matching on [`normalize_tool_name`] instead collapses the casing and
//! separator conventions, so one match arm covers every spelling of a name.
//!
//! [`file_operation_for`] goes one step further for the providers whose hook
//! payload is a bare `tool_name` + `tool_input` envelope — Codex, Hermes,
//! OpenCode, OpenHands. Those hosts constrain neither the name nor the
//! argument keys, so each adapter would otherwise carry its own list and drift
//! from the others. One classifier keeps them together, and keeps each
//! adapter's pre- and post-execution mappers in step: both ask the same
//! question, so a tool adjudicated as a `FileOperation` always reports its
//! result as a `FileOperationResult`.

use serde_json::Value;
use sondera_harness_client::{FileOpType, FileOperation, WebFetch};

/// Fold a tool name to its case- and separator-insensitive form.
///
/// ASCII letters are lowercased; `_`, `-`, and spaces are dropped. `read_file`,
/// `readFile`, `ReadFile`, and `read-file` all fold to `readfile`.
///
/// Folding never merges distinct tools: it removes separators rather than
/// splitting on them, so an MCP tool named `mcp__fs__read_file` folds to
/// `mcpfsreadfile` and stays distinct from the host's own `read_file`.
///
/// ```
/// use sondera_hooks::tool::normalize_tool_name;
///
/// assert_eq!(normalize_tool_name("read_file"), "readfile");
/// assert_eq!(normalize_tool_name("readFile"), "readfile");
/// assert_ne!(normalize_tool_name("mcp__fs__read_file"), "readfile");
/// ```
#[must_use]
pub fn normalize_tool_name(name: &str) -> String {
    name.chars()
        .filter(|c| !matches!(c, '_' | '-' | ' '))
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Argument keys that host agents use for "the file this call touches".
///
/// Ordered most to least specific: a call carrying both `filePath` and a
/// directory `path` should resolve to the file. Gemini CLI uses
/// `absolute_path` on `read_file` but `file_path` on `write_file`, and
/// Antigravity uses PascalCase, so an adapter that reads a single key gets an
/// empty path from the other spellings — and an empty path matches no
/// `context.path_normalized` condition.
pub const FILE_PATH_KEYS: &[&str] = &[
    "filePath",
    "file_path",
    "absolutePath",
    "absolute_path",
    "AbsolutePath",
    "targetFile",
    "target_file",
    "TargetFile",
    "notebook_path",
    "notebookPath",
    "path",
    "Path",
    "file",
    "uri",
];

/// Read the first key present in `args` whose value is a string.
///
/// Keys are matched exactly and in order; use it with [`FILE_PATH_KEYS`] or a
/// provider-specific list.
#[must_use]
pub fn string_arg<'a>(args: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| args.get(*key).and_then(Value::as_str))
}

/// Read the file path out of a tool call's arguments, trying every spelling in
/// [`FILE_PATH_KEYS`].
#[must_use]
pub fn file_path_arg(args: &Value) -> &str {
    string_arg(args, FILE_PATH_KEYS).unwrap_or("")
}

/// Argument keys carrying the content a call writes.
const CONTENT_KEYS: &[&str] = &[
    "content",
    "file_text",
    "fileText",
    "new_str",
    "newStr",
    "new_string",
    "newString",
    "new_content",
    "newContent",
    "text",
    "code",
    "insert_line_content",
];

/// Argument keys carrying the content a call replaces.
const OLD_CONTENT_KEYS: &[&str] = &[
    "old_str",
    "oldStr",
    "old_string",
    "oldString",
    "old_content",
    "oldContent",
];

/// Argument keys carrying a unified diff or patch body.
const PATCH_KEYS: &[&str] = &["patch", "diff", "input"];

/// Tool names, folded, that name their targets inside a diff body rather than
/// in a path argument.
///
/// These are the only tools allowed to produce a [`FileOperation`] with an
/// empty path — see [`file_operation_for`].
const PATCH_TOOLS: &[&str] = &["applypatch", "patch", "applydiff"];

/// Classify a tool name as a file operation.
///
/// Names are matched folded, so every casing and separator spelling of a name
/// resolves the same way. The set is the union across the hosts that ship a
/// bare tool envelope; a name absent from it is not a file tool as far as this
/// classifier is concerned, and the caller should fall back to a generic
/// `ToolCall`.
///
/// Returns `None` for the multiplexed editors, whose operation lives in an
/// argument rather than the name — use [`file_op_for`], which handles both.
fn file_op_for_name(folded: &str) -> Option<FileOpType> {
    let op = match folded {
        "read" | "readfile" | "readfiles" | "readmanyfiles" | "view" | "viewfile" | "openfile" => {
            FileOpType::Read
        }
        "write" | "writefile" | "create" | "createfile" | "newfile" | "savefile" => {
            FileOpType::Write
        }
        "edit"
        | "editfile"
        | "editfiles"
        | "replace"
        | "strreplace"
        | "replaceinfile"
        | "replacestringinfile"
        | "inserteditintofile"
        | "multiedit"
        | "applypatch"
        | "patch"
        | "applydiff" => FileOpType::Edit,
        "delete" | "deletefile" | "removefile" | "rmfile" => FileOpType::Delete,
        _ => return None,
    };
    Some(op)
}

/// Tool names, folded, whose operation is selected by a `command` argument
/// rather than by the name.
///
/// The Anthropic-style text editor tool that OpenHands and several SDK agents
/// expose is one tool with a `command` of `view`, `create`, `str_replace`,
/// `insert`, or `undo_edit`. Mapping the whole tool to `FileEdit` would
/// adjudicate a `view` of a credential file as a write — the read policies
/// still would not fire, which is the bug this module exists to prevent.
/// Kept to the names these tools actually ship under. A bare `editor` or
/// `fileeditor` would be broad enough to capture an unrelated MCP tool.
const MULTIPLEXED_EDITORS: &[&str] = &["strreplaceeditor", "strreplacebasededittool", "texteditor"];

/// Classify a tool call as a file operation, from its name and arguments.
///
/// Handles both the single-purpose tools and the multiplexed editors, whose
/// operation is carried in a `command` argument.
#[must_use]
pub fn file_op_for(tool_name: &str, args: &Value) -> Option<FileOpType> {
    let folded = normalize_tool_name(tool_name);
    if MULTIPLEXED_EDITORS.contains(&folded.as_str()) {
        let command = string_arg(args, &["command", "subcommand", "operation", "action"])
            .map(normalize_tool_name)
            .unwrap_or_default();
        return Some(match command.as_str() {
            "view" | "read" => FileOpType::Read,
            "create" | "write" => FileOpType::Write,
            "delete" | "remove" => FileOpType::Delete,
            // str_replace, insert, undo_edit, and anything this host adds
            // later: treat an unrecognized editor command as a mutation
            // rather than dropping the call.
            _ => FileOpType::Edit,
        });
    }
    file_op_for_name(&folded)
}

/// Build a [`FileOperation`] from a tool call, or `None` when the call is not
/// a file operation this classifier recognizes.
///
/// A call with no path is rejected unless it is a patch tool, which names its
/// targets inside the diff body. This guard matters because the name set has
/// to include bare verbs — OpenCode's tools really are `read`, `write`, and
/// `edit` — and those collide with non-file tools on hosts that let any
/// integration register a name. Reclassifying, say, an issue-tracker `create`
/// carrying a `content` field as a `FileWrite` would run the write-side
/// signature policies against it; on a fail-closed gate that is a spurious
/// **deny** of a legitimate call, not merely a mislabelled log line. Requiring
/// a path keeps the collision harmless: without one, the call falls through to
/// a generic `ToolCall` with its arguments intact.
#[must_use]
pub fn file_operation_for(tool_name: &str, args: &Value, call_id: String) -> Option<FileOperation> {
    let operation = file_op_for(tool_name, args)?;
    let path = file_path_arg(args).to_string();
    let is_patch = PATCH_TOOLS.contains(&normalize_tool_name(tool_name).as_str());
    if path.is_empty() && !is_patch {
        return None;
    }
    let content = string_arg(args, CONTENT_KEYS)
        .or_else(|| string_arg(args, PATCH_KEYS))
        .map(str::to_string);
    // A patch with neither a path nor a body leaves the policy layer nothing
    // to match on, and a generic ToolCall at least preserves the arguments.
    if path.is_empty() && content.is_none() {
        return None;
    }
    Some(FileOperation {
        call_id,
        operation,
        path,
        content,
        old_content: string_arg(args, OLD_CONTENT_KEYS).map(str::to_string),
    })
}

/// Tool names, folded, that retrieve a named URL.
///
/// Search tools are deliberately absent: they take a query rather than a URL,
/// and `WebFetch` requires one. A search modelled with an empty URL would
/// match no `url_parse` condition, so it is left as a generic `ToolCall` where
/// its arguments at least survive.
const WEB_TOOLS: &[&str] = &[
    "webfetch",
    "fetch",
    "fetchwebpage",
    "fetchurl",
    "readurl",
    "readurlcontent",
    "weburl",
    "httprequest",
    "http",
];

/// Argument keys carrying the URL a call retrieves.
const URL_KEYS: &[&str] = &["url", "Url", "URL", "uri", "href", "link"];

/// Whether a tool name denotes a web fetch.
#[must_use]
pub fn is_web_tool(tool_name: &str) -> bool {
    WEB_TOOLS.contains(&normalize_tool_name(tool_name).as_str())
}

/// Build a [`WebFetch`] from a tool call, or `None` when the call is not a web
/// fetch this classifier recognizes.
///
/// Returns `None` when no URL can be recovered — including from a `urls` list,
/// which is how VS Code and several MCP fetchers shape the argument. Without
/// one there is nothing for the `url_parse` conditions to match, so the caller
/// should fall back to a generic `ToolCall`.
#[must_use]
pub fn web_fetch_for(tool_name: &str, args: &Value, call_id: String) -> Option<WebFetch> {
    if !is_web_tool(tool_name) {
        return None;
    }
    let url = string_arg(args, URL_KEYS)
        .map(str::to_string)
        .or_else(|| first_string_in_list(args, &["urls", "links"]))?;
    Some(WebFetch {
        call_id,
        url,
        prompt: string_arg(args, &["prompt", "query", "question", "instructions"])
            .unwrap_or("")
            .to_string(),
    })
}

/// Read the first string out of whichever of `keys` holds a list.
fn first_string_in_list(args: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| {
        args.get(*key)?
            .as_array()?
            .iter()
            .find_map(Value::as_str)
            .map(str::to_string)
    })
}

/// Resolve the URL a web call retrieves, accepting either a URL argument or
/// the `urls` list VS Code and several MCP fetchers use.
///
/// Shared with [`web_fetch_for`] so a post-execution mapper reports the same
/// URL the pre-execution one was adjudicated against.
#[must_use]
pub fn web_url_arg(args: &Value) -> Option<String> {
    string_arg(args, URL_KEYS)
        .map(str::to_string)
        .or_else(|| first_string_in_list(args, &["urls", "links"]))
}

/// Whether this call maps to a [`FileOperation`].
///
/// Defined as "[`file_operation_for`] would build one", not as "the name looks
/// like a file tool" — the two differ, because that builder also requires a
/// path (or a patch body). A post-execution mapper that asks the looser
/// question reports a `FileOperationResult` for a call the pre-execution
/// mapper adjudicated as a generic `ToolCall`, and the two halves of the same
/// tool call disagree about what it was.
#[must_use]
pub fn is_file_operation(tool_name: &str, args: &Value) -> bool {
    file_operation_for(tool_name, args, String::new()).is_some()
}

/// Whether this call maps to a [`WebFetch`].
///
/// Defined as "[`web_fetch_for`] would build one" — see
/// [`is_file_operation`] for why the looser name-only question is the wrong
/// one for a post-execution mapper to ask.
#[must_use]
pub fn is_web_fetch(tool_name: &str, args: &Value) -> bool {
    web_fetch_for(tool_name, args, String::new()).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn folds_casing_and_separators() {
        for spelling in [
            "read_file",
            "readFile",
            "ReadFile",
            "read-file",
            "READ_FILE",
            "read file",
        ] {
            assert_eq!(normalize_tool_name(spelling), "readfile", "{spelling}");
        }
    }

    #[test]
    fn keeps_distinct_tools_distinct() {
        assert_ne!(
            normalize_tool_name("mcp__fs__read_file"),
            normalize_tool_name("read_file")
        );
        assert_ne!(
            normalize_tool_name("read_files"),
            normalize_tool_name("read_file")
        );
        assert_ne!(
            normalize_tool_name("write_file"),
            normalize_tool_name("read_file")
        );
    }

    #[test]
    fn file_path_prefers_the_specific_key() {
        // `read_file` on a directory-scoped call carries both; the file wins.
        let args = json!({ "path": "/repo/src", "filePath": "/repo/src/.env" });
        assert_eq!(file_path_arg(&args), "/repo/src/.env");
    }

    #[test]
    fn file_path_covers_provider_spellings() {
        for key in [
            "filePath",
            "file_path",
            "absolute_path",
            "AbsolutePath",
            "TargetFile",
            "path",
        ] {
            let args = json!({ key: "/repo/.env" });
            assert_eq!(file_path_arg(&args), "/repo/.env", "{key}");
        }
    }

    #[test]
    fn file_path_is_empty_when_absent() {
        assert_eq!(file_path_arg(&json!({ "command": "ls" })), "");
        assert_eq!(file_path_arg(&json!({ "path": 42 })), "");
    }

    // ── File-operation classification ────────────────────────────────────────

    #[test]
    fn classifies_the_single_purpose_tools() {
        let cases: &[(&str, FileOpType)] = &[
            ("read", FileOpType::Read),
            ("read_file", FileOpType::Read),
            ("view", FileOpType::Read),
            ("write", FileOpType::Write),
            ("write_file", FileOpType::Write),
            ("create", FileOpType::Write),
            ("edit", FileOpType::Edit),
            ("replace", FileOpType::Edit),
            ("str_replace", FileOpType::Edit),
            ("apply_patch", FileOpType::Edit),
            ("delete_file", FileOpType::Delete),
        ];
        for (tool, expected) in cases {
            assert_eq!(
                file_op_for(tool, &json!({ "path": "/repo/.env" })),
                Some(*expected),
                "{tool}"
            );
        }
    }

    #[test]
    fn shell_and_search_tools_are_not_file_operations() {
        for tool in [
            "bash",
            "shell",
            "terminal",
            "grep",
            "glob",
            "list",
            "todowrite",
        ] {
            assert_eq!(
                file_op_for(tool, &json!({ "path": "/repo" })),
                None,
                "{tool}"
            );
        }
    }

    #[test]
    fn multiplexed_editor_dispatches_on_its_command() {
        // A `view` mapped to Edit would adjudicate a credential read as a
        // write, and the read policies still would not fire.
        let cases: &[(&str, FileOpType)] = &[
            ("view", FileOpType::Read),
            ("create", FileOpType::Write),
            ("str_replace", FileOpType::Edit),
            ("insert", FileOpType::Edit),
            ("undo_edit", FileOpType::Edit),
        ];
        for (command, expected) in cases {
            let args = json!({ "command": command, "path": "/repo/.env" });
            assert_eq!(
                file_op_for("str_replace_editor", &args),
                Some(*expected),
                "{command}"
            );
        }
    }

    #[test]
    fn unrecognized_editor_command_stays_a_mutation() {
        let args = json!({ "command": "some_future_op", "path": "/repo/.env" });
        assert_eq!(
            file_op_for("str_replace_editor", &args),
            Some(FileOpType::Edit)
        );
    }

    #[test]
    fn file_operation_carries_path_and_both_contents() {
        let op = file_operation_for(
            "str_replace",
            &json!({"path": "/repo/app.rs", "old_str": "a", "new_str": "b"}),
            "call-1".to_string(),
        )
        .expect("str_replace is a file operation");
        assert_eq!(op.path, "/repo/app.rs");
        assert_eq!(op.operation, FileOpType::Edit);
        assert_eq!(op.old_content.as_deref(), Some("a"));
        assert_eq!(op.content.as_deref(), Some("b"));
        assert_eq!(op.call_id, "call-1");
    }

    #[test]
    fn patch_body_becomes_content_when_there_is_no_path() {
        let op = file_operation_for(
            "apply_patch",
            &json!({"patch": "--- a/.env\n+++ b/.env\n+SECRET=1\n"}),
            "call-2".to_string(),
        )
        .expect("a patch with a body is still adjudicable");
        assert!(op.path.is_empty());
        assert!(op.content.as_deref().unwrap().contains("SECRET=1"));
    }

    #[test]
    fn declines_a_call_with_neither_path_nor_content() {
        // Nothing for the path conditions or the signature scan to match, and
        // a generic ToolCall at least preserves the raw arguments.
        assert!(file_operation_for("edit", &json!({"selection": 3}), "c".into()).is_none());
        assert!(file_operation_for("bash", &json!({"command": "ls"}), "c".into()).is_none());
    }

    #[test]
    fn a_pathless_non_patch_call_is_not_a_file_operation() {
        // The name set has to include bare verbs, which collide with non-file
        // tools. Reclassifying an issue-tracker `create` as a FileWrite would
        // run the write-side signature policies against its body — a spurious
        // deny on a fail-closed gate, not just a mislabelled log line.
        for tool in ["create", "write", "edit", "delete", "read"] {
            assert!(
                file_operation_for(tool, &json!({"title": "x", "content": "body"}), "c".into())
                    .is_none(),
                "{tool} without a path must fall through to a generic ToolCall"
            );
        }
        // Give the same call a path and it is a file operation again.
        assert!(
            file_operation_for(
                "create",
                &json!({"path": "/repo/x", "content": "b"}),
                "c".into()
            )
            .is_some()
        );
    }

    // ── Web-fetch classification ─────────────────────────────────────────────

    #[test]
    fn classifies_the_web_tools() {
        for tool in [
            "web_fetch",
            "webFetch",
            "fetch",
            "fetch_webpage",
            "read_url_content",
        ] {
            let fetch = web_fetch_for(tool, &json!({"url": "https://example.com"}), "c".into())
                .unwrap_or_else(|| panic!("{tool} should be a web fetch"));
            assert_eq!(fetch.url, "https://example.com");
        }
    }

    #[test]
    fn web_fetch_reads_a_urls_list() {
        // VS Code's fetch_webpage and several MCP fetchers pass `urls: [...]`.
        let fetch = web_fetch_for(
            "fetch_webpage",
            &json!({"urls": ["https://example.com/a"], "query": "api key"}),
            "c".into(),
        )
        .expect("a urls list still names a URL");
        assert_eq!(fetch.url, "https://example.com/a");
        assert_eq!(fetch.prompt, "api key");
    }

    #[test]
    fn a_urlless_call_is_not_a_web_fetch() {
        // Nothing for the url_parse conditions to match; a generic ToolCall
        // at least preserves the arguments.
        assert!(web_fetch_for("fetch", &json!({"id": 7}), "c".into()).is_none());
        assert!(web_fetch_for("fetch", &json!({"urls": []}), "c".into()).is_none());
    }

    #[test]
    fn the_predicates_agree_with_the_builders() {
        // The post-execution mappers gate on these; the pre-execution ones
        // gate on the builders. Any divergence means the two halves of one
        // tool call disagree about what it was — a FileOperationResult for a
        // call adjudicated as a generic ToolCall.
        let cases: &[(&str, serde_json::Value)] = &[
            ("create", json!({"title": "x", "content": "body"})),
            ("create", json!({"path": "/repo/x", "content": "body"})),
            ("read", json!({"id": 3})),
            ("apply_patch", json!({"patch": "diff"})),
            ("apply_patch", json!({})),
            ("fetch", json!({"id": 7})),
            ("fetch", json!({"url": "https://example.com"})),
            ("fetch", json!({"urls": ["https://example.com"]})),
            ("bash", json!({"command": "ls"})),
        ];
        for (tool, args) in cases {
            assert_eq!(
                is_file_operation(tool, args),
                file_operation_for(tool, args, "c".into()).is_some(),
                "file predicate disagrees for {tool} {args}"
            );
            assert_eq!(
                is_web_fetch(tool, args),
                web_fetch_for(tool, args, "c".into()).is_some(),
                "web predicate disagrees for {tool} {args}"
            );
        }
    }

    #[test]
    fn the_name_only_question_is_the_looser_one() {
        // Documents why the post-execution mappers must not gate on
        // `file_op_for` / `is_web_tool`: those say yes where the builders say
        // no, which is exactly the drift the predicates above prevent.
        let pathless = json!({"content": "body"});
        assert!(file_op_for("create", &pathless).is_some());
        assert!(!is_file_operation("create", &pathless));

        let urlless = json!({"id": 7});
        assert!(is_web_tool("fetch"));
        assert!(!is_web_fetch("fetch", &urlless));
    }

    #[test]
    fn web_url_arg_matches_what_web_fetch_for_resolves() {
        for args in [
            json!({"url": "https://example.com/a"}),
            json!({"urls": ["https://example.com/a"]}),
        ] {
            assert_eq!(
                web_url_arg(&args).as_deref(),
                web_fetch_for("fetch", &args, "c".into())
                    .map(|f| f.url)
                    .as_deref()
            );
        }
    }

    #[test]
    fn search_tools_are_not_web_fetches() {
        // A search takes a query, not a URL, so WebFetch cannot model it.
        for tool in ["web_search", "google_web_search", "search", "grep"] {
            assert!(!is_web_tool(tool), "{tool}");
        }
    }

    #[test]
    fn only_patch_tools_may_go_without_a_path() {
        let body = json!({"patch": "--- a/.env\n+++ b/.env\n"});
        assert!(file_operation_for("apply_patch", &body, "c".into()).is_some());
        assert!(file_operation_for("edit", &body, "c".into()).is_none());
    }

    #[test]
    fn openhands_editor_view_is_a_read() {
        let op = file_operation_for(
            "str_replace_editor",
            &json!({"command": "view", "path": "/repo/.env"}),
            "call-3".to_string(),
        )
        .expect("an editor view is a file read");
        assert_eq!(op.operation, FileOpType::Read);
        assert_eq!(op.path, "/repo/.env");
    }

    #[test]
    fn openhands_editor_create_carries_file_text() {
        let op = file_operation_for(
            "str_replace_editor",
            &json!({"command": "create", "path": "/repo/.env", "file_text": "TOKEN=abc"}),
            "call-4".to_string(),
        )
        .expect("an editor create is a file write");
        assert_eq!(op.operation, FileOpType::Write);
        assert_eq!(op.content.as_deref(), Some("TOKEN=abc"));
    }
}
