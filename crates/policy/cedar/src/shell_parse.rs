//! Structured shell-command parsing for Cedar context via tree-sitter-bash.
//!
//! Parses a shell command string into a flattened [`ShellParse`] record so
//! policies can match on programs/flags/args structurally instead of brittle
//! `command like "*rm -rf*"` globs. Cedar has no ordered lists and no
//! per-element set predicates, so structure is encoded as string sets with a
//! `program:token` pair scheme (program lowercased basename, token after shell
//! quote removal).
//!
//! The parser is INFALLIBLE by design: any failure (grammar load error,
//! `parse()` returning `None`, syntax errors, oversized input) degrades to
//! `ok: false` plus empty sets. A guardrail must never abort adjudication.

use std::collections::BTreeSet;

/// Commands larger than this skip parsing entirely (`ok: false`, empty sets)
/// to bound worst-case parse time on the adjudication path.
const MAX_COMMAND_BYTES: usize = 256 * 1024;

/// Cap on `bash -c` / `eval` re-parse recursion.
const MAX_REPARSE_DEPTH: usize = 4;

/// Cap on tree-walk recursion depth. Adversarial input (e.g. 256 KiB of
/// nested `$(`) can produce trees deep enough to overflow the stack; beyond
/// this depth we stop descending and mark the parse incomplete. Infallibility
/// (never crash adjudication) outranks completeness here.
const MAX_TREE_DEPTH: usize = 512;

/// A command whose first positional argument is itself a command (e.g.
/// `sudo rm -rf /`). `value_flags` lists the wrapper's own option flags —
/// short and long together — that consume the following token as a value, so
/// it is not mistaken for the nested command (`sudo -u alice rm` → `alice` is
/// the value of `-u`, not the nested program).
struct Wrapper {
    name: &'static str,
    value_flags: &'static [&'static str],
}

/// Single source of truth for wrapper peeling: membership AND each wrapper's
/// value-consuming flags live in one table so the two cannot drift.
const WRAPPERS: &[Wrapper] = &[
    Wrapper {
        name: "sudo",
        value_flags: &[
            "-u",
            "-g",
            "-p",
            "-C",
            "-D",
            "-h",
            "-R",
            "-T",
            "-U",
            "-r",
            "-t",
            "--user",
            "--group",
            "--prompt",
            "--close-from",
            "--chdir",
            "--host",
            "--role",
            "--type",
            "--login-class",
        ],
    },
    Wrapper {
        name: "doas",
        value_flags: &["-u", "-C"],
    },
    Wrapper {
        name: "xargs",
        value_flags: &[
            "-a",
            "-d",
            "-E",
            "-e",
            "-I",
            "-i",
            "-L",
            "-l",
            "-n",
            "-P",
            "-s",
            "--arg-file",
            "--delimiter",
            "--eof",
            "--replace",
            "--max-lines",
            "--max-args",
            "--max-procs",
            "--max-chars",
            "--process-slot-var",
        ],
    },
    Wrapper {
        name: "timeout",
        value_flags: &["-s", "-k", "--signal", "--kill-after"],
    },
    Wrapper {
        name: "nice",
        value_flags: &["-n", "--adjustment"],
    },
    Wrapper {
        name: "env",
        value_flags: &[
            "-u",
            "-S",
            "-C",
            "--unset",
            "--chdir",
            "--split-string",
            "--argv0",
        ],
    },
    Wrapper {
        name: "stdbuf",
        value_flags: &["-i", "-o", "-e", "--input", "--output", "--error"],
    },
    Wrapper {
        name: "exec",
        value_flags: &["-a"],
    },
    Wrapper {
        name: "nohup",
        value_flags: &[],
    },
    Wrapper {
        name: "setsid",
        value_flags: &[],
    },
    Wrapper {
        name: "command",
        value_flags: &[],
    },
];

/// Look up a wrapper spec by its (lowercased) program name.
fn wrapper_spec(name: &str) -> Option<&'static Wrapper> {
    WRAPPERS.iter().find(|w| w.name == name)
}

/// Shells whose `-c <script>` argument is re-parsed (depth-capped).
const SHELLS: &[&str] = &["bash", "sh", "zsh", "dash", "ash"];

/// True for a token that reads as an option flag rather than a positional
/// (`-r`, `-rf`, `--force`). A bare `-` is positional (stdin), as is `--`
/// (handled separately as the options terminator).
fn is_flag_token(text: &str) -> bool {
    text.starts_with('-') && text.len() > 1
}

/// Whether `text` is one of `wrapper`'s value-consuming option flags (so the
/// next token is its value, not the nested command). `--flag=value` carries
/// its own value inline, so it never consumes the following token.
fn wrapper_flag_consumes_value(wrapper: &Wrapper, text: &str) -> bool {
    !text.contains('=') && wrapper.value_flags.contains(&text)
}

use super::path_normalize::normalize_path_value;

/// Structured view of a shell command extracted via tree-sitter-bash.
/// Deterministic: all sets are `BTreeSet<String>` so serialized JSON is stable.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ShellParse {
    /// Complete parse: no syntax errors and no truncated tree walk.
    ok: bool,
    /// Lowercased basename of every command-position word, across pipelines,
    /// `&&`/`;` chains, `$()`, subshells, and peeled wrappers.
    programs: BTreeSet<String>,
    /// `"rm:-r"` — flags scoped per (lowercased) program after quote removal.
    /// Bundled alphabetic shorts are split AND the raw cluster is kept.
    program_flags: BTreeSet<String>,
    /// Case/separator-folded companion to `program_flags`.
    program_flags_normalized: BTreeSet<String>,
    /// `"rm:/"` — literal positional args scoped per program after quote
    /// removal.
    program_args: BTreeSet<String>,
    /// Case/separator-folded companion to `program_args`.
    program_args_normalized: BTreeSet<String>,
    /// Normalized path components from literal positional args, scoped per
    /// program as `"program:component"` for anchored directory/file matching.
    program_arg_path_components_normalized: BTreeSet<String>,
    /// An expansion/substitution appears in a command-NAME position.
    has_dynamic_command: bool,
    has_command_substitution: bool,
    has_pipeline: bool,
    has_redirection: bool,
}

impl ShellParse {
    /// Cedar context fragment. Field names/types match `ShellParseContext`
    /// in the schema. Sets serialize as sorted JSON arrays (Cedar `Set<String>`).
    pub(crate) fn to_cedar_json(&self) -> serde_json::Value {
        serde_json::json!({
            "ok": self.ok,
            "programs": self.programs.iter().collect::<Vec<_>>(),
            "program_flags": self.program_flags.iter().collect::<Vec<_>>(),
            "program_flags_normalized": self.program_flags_normalized.iter().collect::<Vec<_>>(),
            "program_args": self.program_args.iter().collect::<Vec<_>>(),
            "program_args_normalized": self.program_args_normalized.iter().collect::<Vec<_>>(),
            "program_arg_path_components_normalized": self.program_arg_path_components_normalized.iter().collect::<Vec<_>>(),
            "has_dynamic_command": self.has_dynamic_command,
            "has_command_substitution": self.has_command_substitution,
            "has_pipeline": self.has_pipeline,
            "has_redirection": self.has_redirection,
        })
    }

    /// Fold a nested re-parse (`bash -c`, `eval`) into this record:
    /// set union, bool OR, `ok` AND (a broken inner script lowers `ok`).
    fn merge(&mut self, other: ShellParse) {
        self.ok &= other.ok;
        self.programs.extend(other.programs);
        self.program_flags.extend(other.program_flags);
        self.program_flags_normalized
            .extend(other.program_flags_normalized);
        self.program_args.extend(other.program_args);
        self.program_args_normalized
            .extend(other.program_args_normalized);
        self.program_arg_path_components_normalized
            .extend(other.program_arg_path_components_normalized);
        self.has_dynamic_command |= other.has_dynamic_command;
        self.has_command_substitution |= other.has_command_substitution;
        self.has_pipeline |= other.has_pipeline;
        self.has_redirection |= other.has_redirection;
    }
}

/// Working state threaded through the single tree-sitter pass. Folded across
/// `bash -c`/`eval` re-parses by [`ShellScan::merge`].
///
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ShellScan {
    parse: ShellParse,
}

impl ShellScan {
    /// Fold a nested re-parse into this scan (see [`ShellParse::merge`]).
    fn merge(&mut self, other: ShellScan) {
        self.parse.merge(other.parse);
    }
}

/// Analyze `command` into a [`ShellParse`]. Infallible: on any parse failure
/// returns a default (`ok = false`, empty sets).
pub(crate) fn analyze_shell_command(command: &str) -> ShellParse {
    parse_with_depth(command, 0).parse
}

fn parse_with_depth(command: &str, reparse_depth: usize) -> ShellScan {
    if command.len() > MAX_COMMAND_BYTES {
        return ShellScan::default();
    }
    let mut parser = tree_sitter::Parser::new();
    if parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .is_err()
    {
        return ShellScan::default();
    }
    let Some(tree) = parser.parse(command, None) else {
        return ShellScan::default();
    };
    let root = tree.root_node();
    let mut out = ShellScan {
        parse: ShellParse {
            // has_error() is true for ERROR and MISSING nodes anywhere in the tree.
            ok: !root.has_error(),
            ..Default::default()
        },
    };
    let walk = Walk {
        src: command.as_bytes(),
        reparse_depth,
        tree_depth: 0,
    };
    visit(root, walk, &mut out);
    out
}

/// Immutable walk state threaded (by `Copy`) through the recursive
/// extraction. Bundles the source bytes with two independent depth counters
/// whose scopes differ deliberately: `reparse_depth` accumulates ACROSS trees
/// (each `bash -c`/`eval` re-parse), while `tree_depth` is reset per tree and
/// tracks recursion WITHIN one tree.
#[derive(Clone, Copy)]
struct Walk<'a> {
    src: &'a [u8],
    /// `bash -c` / `eval` re-parse depth, threaded across re-parses and capped
    /// at [`MAX_REPARSE_DEPTH`].
    reparse_depth: usize,
    /// Recursion depth within the current tree, reset to 0 on each re-parse
    /// and capped at [`MAX_TREE_DEPTH`].
    tree_depth: usize,
}

impl Walk<'_> {
    fn deeper(self) -> Self {
        Self {
            tree_depth: self.tree_depth + 1,
            ..self
        }
    }
}

/// Recursive tree walk: set structural flags, hand `command` nodes to
/// [`handle_command`], and generically recurse everything else (lists,
/// subshells, control flow, function bodies, substitution interiors, ...).
fn visit(node: tree_sitter::Node, walk: Walk, out: &mut ShellScan) {
    if walk.tree_depth > MAX_TREE_DEPTH {
        // Truncated walk: extraction below this point is incomplete.
        out.parse.ok = false;
        return;
    }
    match node.kind() {
        "pipeline" => out.parse.has_pipeline = true,
        "command_substitution" | "process_substitution" => {
            out.parse.has_command_substitution = true;
        }
        "file_redirect" | "heredoc_redirect" | "herestring_redirect" => {
            out.parse.has_redirection = true;
        }
        "command" => {
            handle_command(node, walk, out);
            return;
        }
        _ => {}
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        visit(child, walk.deeper(), out);
    }
}

/// Extract program/flags/args from a `command` node (fields `name:` and
/// `argument:`). Non-name, non-argument children (variable_assignment
/// prefixes, inline redirects) are walked generically so embedded `$()`
/// is still mined.
fn handle_command(node: tree_sitter::Node, walk: Walk, out: &mut ShellScan) {
    let mut name_node = None;
    let mut args = Vec::new();
    let mut cursor = node.walk();
    if cursor.goto_first_child() {
        loop {
            let child = cursor.node();
            if child.is_named() {
                match cursor.field_name() {
                    Some("name") => name_node = Some(child),
                    Some("argument") => args.push(child),
                    _ => visit(child, walk.deeper(), out),
                }
            }
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }

    // The `name` field is a `command_name` node wrapping a single word-like
    // child; resolve it to a literal program or mark the command dynamic.
    let inner = name_node.and_then(|n| n.named_child(0));
    let Some(inner) = inner else {
        // Defensive: command with no resolvable name — mine args and stop.
        mine_args(&args, walk, out);
        return;
    };
    let Some(text) = literal_text(inner, walk.src) else {
        // Dynamic command name ($VAR, $(...)): no program scope for args.
        // Still recurse so inner substitutions yield their own programs.
        out.parse.has_dynamic_command = true;
        visit(inner, walk.deeper(), out);
        mine_args(&args, walk, out);
        return;
    };
    let prog = normalize_program(&text);
    if prog.is_empty() {
        mine_args(&args, walk, out);
        return;
    }
    // Classify before inserting so the owned `prog` can be moved into the set
    // (classify_invocation only borrows it) — no clone.
    classify_invocation(&prog, &args, walk, out);
    out.parse.programs.insert(prog);
}

/// Recurse into each argument to mine embedded substitutions/programs without
/// scoping them to a missing or dynamic command name.
fn mine_args(args: &[tree_sitter::Node], walk: Walk, out: &mut ShellScan) {
    for arg in args {
        visit(*arg, walk.deeper(), out);
    }
}

/// Classify an argument list under a resolved program, dispatching wrapper
/// peeling, shell `-c` recursion, and `eval` recursion.
fn classify_invocation(prog: &str, args: &[tree_sitter::Node], walk: Walk, out: &mut ShellScan) {
    // Bound this recursion the way `visit` bounds the tree walk:
    // classify_invocation re-enters itself through `peel_wrapper` for nested
    // wrappers (`sudo sudo … rm`), a cycle that never passes back through
    // `visit`. Without this guard a long flat wrapper chain recurses one
    // native stack frame per token and aborts the process on stack overflow —
    // breaking the infallibility contract.
    if walk.tree_depth > MAX_TREE_DEPTH {
        out.parse.ok = false;
        return;
    }
    if let Some(spec) = wrapper_spec(prog) {
        peel_wrapper(spec, args, walk, out);
        return;
    }
    if prog == "eval" {
        handle_eval(args, walk, out);
        return;
    }
    if SHELLS.contains(&prog)
        && let Some((script_idx, script)) = find_c_script(args, walk.src)
    {
        if walk.reparse_depth < MAX_REPARSE_DEPTH {
            let sub = parse_with_depth(&script, walk.reparse_depth + 1);
            out.merge(sub);
        } else {
            out.parse.ok = false;
        }
        // The script is decomposed above; classify the shell's own flags/args
        // but skip the script token so it is not also filed as a literal
        // positional (`bash:rm -rf /`).
        classify_args(prog, args, Some(script_idx), walk, out);
        return;
    }
    classify_args(prog, args, None, walk, out);
}

/// Classify each argument under `prog`, optionally skipping one already-
/// consumed token (e.g. a shell `-c` script that was re-parsed instead).
fn classify_args(
    prog: &str,
    args: &[tree_sitter::Node],
    skip: Option<usize>,
    walk: Walk,
    out: &mut ShellScan,
) {
    let mut positional_only = false;
    for (idx, arg) in args.iter().enumerate() {
        if Some(idx) == skip {
            continue;
        }
        classify_arg(prog, *arg, walk, out, &mut positional_only);
    }
}

/// Classify a single argument node under `prog` per the extraction rules:
/// `--` terminator, bare `-` positional, long flags (`--opt=val` → `--opt`),
/// short clusters (raw kept + alphabetic-only split), literal positionals.
/// Dynamic args are walked for nested substitutions but never emitted.
fn classify_arg(
    prog: &str,
    arg: tree_sitter::Node,
    walk: Walk,
    out: &mut ShellScan,
    positional_only: &mut bool,
) {
    let Some(text) = literal_text(arg, walk.src) else {
        visit(arg, walk.deeper(), out);
        return;
    };
    if *positional_only {
        insert_arg(
            prog,
            &text,
            raw_windows_path_source(arg, walk.src),
            &mut out.parse,
        );
        return;
    }
    if text == "--" {
        *positional_only = true;
        return;
    }
    if !is_flag_token(&text) {
        // Literal positional (a bare `-` counts as positional, e.g. stdin).
        insert_arg(
            prog,
            &text,
            raw_windows_path_source(arg, walk.src),
            &mut out.parse,
        );
        return;
    }
    insert_flag(prog, &text, &mut out.parse);
}

fn insert_arg(prog: &str, text: &str, raw_windows_source: Option<&str>, out: &mut ShellParse) {
    out.program_args.insert(format!("{prog}:{text}"));
    let normalized = normalize_path_value(text);
    insert_normalized_arg_view(prog, &normalized, out);

    if let Some(raw_source) = raw_windows_source {
        let raw_normalized = normalize_path_value(raw_source);
        if raw_normalized != normalized {
            insert_normalized_arg_view(prog, &raw_normalized, out);
        }
    }
}

fn insert_normalized_arg_view(prog: &str, normalized: &str, out: &mut ShellParse) {
    out.program_args_normalized
        .insert(format!("{prog}:{normalized}"));
    for component in normalized
        .split('/')
        .filter(|component| !component.is_empty())
    {
        out.program_arg_path_components_normalized
            .insert(format!("{prog}:{component}"));
    }
}

fn raw_windows_path_source<'a>(arg: tree_sitter::Node, src: &'a [u8]) -> Option<&'a str> {
    if !matches!(arg.kind(), "word" | "number") {
        return None;
    }
    let text = arg.utf8_text(src).ok()?;
    if looks_like_raw_windows_path(text) {
        Some(text)
    } else {
        None
    }
}

fn looks_like_raw_windows_path(text: &str) -> bool {
    let bytes = text.as_bytes();
    let has_drive_prefix = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/');
    text.starts_with(r"\\")
        || text.starts_with(".\\")
        || text.starts_with("..\\")
        || text
            .strip_prefix('\\')
            .is_some_and(looks_like_relative_windows_path)
        || looks_like_relative_windows_path(text)
        || has_drive_prefix
}

fn looks_like_relative_windows_path(text: &str) -> bool {
    let mut components = text.split('\\');
    let Some(mut previous) = components.next() else {
        return false;
    };
    if previous.is_empty() {
        return false;
    }

    for current in components {
        if current.is_empty() {
            return false;
        }
        // Bare Bash words with backslashes are ambiguous. Add a raw Windows
        // companion only when a separator has path-shaped evidence on both
        // sides; a dot-starting fragment after the separator is not enough
        // evidence by itself because it is also common in escaped extensions.
        if can_precede_relative_windows_separator(previous)
            && can_signal_relative_windows_path_after_separator(current)
        {
            return true;
        }
        previous = current;
    }
    false
}

fn can_precede_relative_windows_separator(component: &str) -> bool {
    component
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_'))
}

fn can_signal_relative_windows_path_after_separator(component: &str) -> bool {
    component
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'*' | b'?'))
}

/// Record a flag token under `prog`. Long flags drop an `=value` suffix.
/// Short clusters keep the raw token AND split into singletons when the
/// body is purely alphabetic — a documented over-approximation (`-rf` →
/// `-r` + `-f`); digit/path bodies (`-O2`, `-I/usr`, `-9`) stay raw-only
/// because the suffix is likely an attached value, not bundled flags.
fn insert_flag(prog: &str, text: &str, out: &mut ShellParse) {
    if let Some(rest) = text.strip_prefix("--") {
        let name = rest.split_once('=').map_or(rest, |(name, _)| name);
        let raw = format!("{prog}:--{name}");
        out.program_flags.insert(raw);
        out.program_flags_normalized
            .insert(format!("{prog}:--{}", normalize_path_value(name)));
        return;
    }
    out.program_flags.insert(format!("{prog}:{text}"));
    out.program_flags_normalized
        .insert(format!("{prog}:{}", normalize_path_value(text)));
    let Some(body) = text.strip_prefix('-') else {
        return;
    };
    if !body.is_empty() && body.chars().all(|c| c.is_ascii_alphabetic()) {
        for c in body.chars() {
            let singleton = format!("-{c}");
            out.program_flags.insert(format!("{prog}:{singleton}"));
            out.program_flags_normalized
                .insert(format!("{prog}:{}", normalize_path_value(&singleton)));
        }
    }
}

/// Re-scope a wrapper's argument list: the wrapper's own flags record under
/// the wrapper, the first positional (after wrapper-specific skips) becomes a
/// nested program, and the remaining args classify under it. Nested wrappers
/// peel again — bounded, since each peel consumes at least one token.
fn peel_wrapper(wrapper: &Wrapper, args: &[tree_sitter::Node], walk: Walk, out: &mut ShellScan) {
    // `timeout DURATION cmd`: the duration is timeout's own positional.
    let mut skip_positionals = usize::from(wrapper.name == "timeout");
    let mut opts_ended = false;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i];
        let Some(text) = literal_text(arg, walk.src) else {
            // A dynamic token in the nested-command-name position ($CMD,
            // $(...)): the real program is unknown, so its flags/args must NOT
            // be scoped to the wrapper. Mark dynamic, mine this and the
            // remaining tokens for embedded substitutions, then stop — mirrors
            // handle_command's dynamic-name path. (A dynamic flag *value* is
            // already consumed by the value-flag arm below, so reaching here
            // means the token sits where the nested command would.)
            out.parse.has_dynamic_command = true;
            mine_args(&args[i..], walk, out);
            return;
        };
        if !opts_ended {
            if text == "--" {
                opts_ended = true;
                i += 1;
                continue;
            }
            if wrapper.name == "env" && is_env_assignment(&text) {
                i += 1;
                continue;
            }
            if is_flag_token(&text) {
                insert_flag(wrapper.name, &text, &mut out.parse);
                if wrapper_flag_consumes_value(wrapper, &text) {
                    // Consume the flag's value; still mine a dynamic value
                    // (e.g. `sudo -u $(whoami) ...`) for substitutions.
                    if let Some(value) = args.get(i + 1)
                        && literal_text(*value, walk.src).is_none()
                    {
                        visit(*value, walk.deeper(), out);
                    }
                    i += 2;
                } else {
                    i += 1;
                }
                continue;
            }
        }
        if skip_positionals > 0 {
            skip_positionals -= 1;
            insert_arg(
                wrapper.name,
                &text,
                raw_windows_path_source(arg, walk.src),
                &mut out.parse,
            );
            i += 1;
            continue;
        }
        let nested = normalize_program(&text);
        if nested.is_empty() {
            insert_arg(
                wrapper.name,
                &text,
                raw_windows_path_source(arg, walk.src),
                &mut out.parse,
            );
            i += 1;
            continue;
        }
        // `.deeper()` so the nested invocation counts against MAX_TREE_DEPTH;
        // classify before inserting so the owned `nested` moves into the set.
        classify_invocation(&nested, &args[i + 1..], walk.deeper(), out);
        out.parse.programs.insert(nested);
        return;
    }
}

/// `eval`: join the literal arguments into one script string and re-parse it
/// through the same depth-capped machinery as `bash -c`. Dynamic args stay
/// opaque but are still mined for embedded `$()`.
fn handle_eval(args: &[tree_sitter::Node], walk: Walk, out: &mut ShellScan) {
    let mut parts = Vec::new();
    for arg in args {
        match literal_text(*arg, walk.src) {
            Some(text) => parts.push(text),
            None => visit(*arg, walk.deeper(), out),
        }
    }
    if parts.is_empty() {
        return;
    }
    if walk.reparse_depth >= MAX_REPARSE_DEPTH {
        out.parse.ok = false;
        return;
    }
    let sub = parse_with_depth(&parts.join(" "), walk.reparse_depth + 1);
    out.merge(sub);
}

/// Locate the literal script following a `-c` (or short cluster containing
/// `c`, e.g. `-lc`) in a shell invocation's arguments, returning its argument
/// index and text so the caller can re-parse it and skip re-classifying it.
fn find_c_script(args: &[tree_sitter::Node], src: &[u8]) -> Option<(usize, String)> {
    let mut seen_c = false;
    for (idx, arg) in args.iter().enumerate() {
        let Some(text) = literal_text(*arg, src) else {
            continue;
        };
        if seen_c {
            if !text.starts_with('-') {
                return Some((idx, text));
            }
        } else if let Some(body) = text.strip_prefix('-')
            && !body.starts_with('-')
            && body.contains('c')
        {
            seen_c = true;
        }
    }
    None
}

/// `NAME=value` tokens that `env` consumes before the nested command.
fn is_env_assignment(text: &str) -> bool {
    match text.split_once('=') {
        Some((name, _)) => {
            !name.is_empty()
                && !name.starts_with(|c: char| c.is_ascii_digit())
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    }
}

/// Basename + lowercase + trailing `.exe` strip: `/bin/RM` → `rm`,
/// `C:\Windows\System32\PowerShell.EXE` → `powershell`. Lowercasing matches
/// macOS/Windows case-insensitive command lookup; on Linux it errs toward
/// over-blocking, which is the accepted direction for a guardrail signal.
fn normalize_program(text: &str) -> String {
    let basename = text.rsplit(['/', '\\']).next().unwrap_or("").to_lowercase();
    basename
        .strip_suffix(".exe")
        .unwrap_or(&basename)
        .to_string()
}

/// Resolve a word-like node to its literal text, or `None` when it is (or
/// contains) an expansion/substitution and must be treated as dynamic.
fn literal_text(node: tree_sitter::Node, src: &[u8]) -> Option<String> {
    match node.kind() {
        "word" => node_text(node, src).map(|text| unescape_unquoted_word(&text)),
        "number" => {
            // A plain integer is literal. The base-N form `64#$(...)` /
            // `64#${...}` wraps an expansion/command-substitution child — treat
            // it as dynamic (return None) so the caller recurses into it
            // instead of filing the whole token as a literal positional, which
            // would hide the inner command and leave has_command_substitution
            // unset.
            if node.named_child_count() == 0 {
                node_text(node, src).map(|text| unescape_unquoted_word(&text))
            } else {
                None
            }
        }
        "raw_string" => {
            let text = node_text(node, src)?;
            let inner = text
                .strip_prefix('\'')
                .and_then(|s| s.strip_suffix('\''))
                .unwrap_or(&text);
            Some(inner.to_string())
        }
        "ansi_c_string" => {
            // $'...' — decode the escapes so the token matches the argv word the
            // program receives. See `unescape_ansi_c` for why leaving
            // them verbatim was a bypass and not merely an imprecision.
            let text = node_text(node, src)?;
            let Some(inner) = text.strip_prefix("$'").and_then(|s| s.strip_suffix('\'')) else {
                // Error-recovered node (an unterminated `$'…`): the delimiters
                // are not where the grammar promises, so there is no body to
                // decode. Return the raw text — decoding a token whose extent we
                // do not trust could strip backslashes that are really content.
                return Some(text);
            };
            Some(unescape_ansi_c(inner))
        }
        "string" => {
            // A double-quoted string is literal iff it has no expansion or
            // command substitution. Reconstruct from the full node text (minus
            // the surrounding quotes) so literal `$` and other anonymous tokens
            // are preserved — concatenating only the `string_content` named
            // children would silently drop a literal `$` (e.g. `"price$"`).
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                if child.kind() != "string_content" {
                    return None;
                }
            }
            let text = node_text(node, src)?;
            let inner = text
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or(&text);
            Some(unescape_double_quoted(inner))
        }
        "concatenation" => {
            // ab"c"d — literal iff every part is literal.
            let mut cursor = node.walk();
            let mut content = String::new();
            for child in node.named_children(&mut cursor) {
                content.push_str(&literal_text(child, src)?);
            }
            Some(content)
        }
        _ => None,
    }
}

fn node_text(node: tree_sitter::Node, src: &[u8]) -> Option<String> {
    node.utf8_text(src).ok().map(str::to_string)
}

fn unescape_unquoted_word(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('\n') => {}
            Some(next) => out.push(next),
            None => out.push('\\'),
        }
    }
    out
}

/// Remove the backslash escapes that are special inside double quotes (`\"`,
/// `\\`, `\$`, `` \` ``, and line-continuation `\<newline>`). A backslash
/// before any other character is literal, per POSIX double-quote rules.
fn unescape_double_quoted(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('\n') => {}
            Some(next @ ('"' | '\\' | '$' | '`')) => out.push(next),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// Consume up to `max` hex digits starting at `*i`, returning the value and the
/// number of digits read. Reads FEWER than `max` happily: bash accepts `$'\xA'`
/// and `$'\u41'`, so requiring the full width would mis-decode valid input.
fn take_hex(src: &[u8], i: &mut usize, max: usize) -> (u32, usize) {
    let mut value = 0u32;
    let mut digits = 0;
    while digits < max {
        let Some(d) = src.get(*i).and_then(|c| (*c as char).to_digit(16)) else {
            break;
        };
        value = value * 16 + d;
        *i += 1;
        digits += 1;
    }
    (value, digits)
}

/// Decode the body of an ANSI-C quoted word (`$'...'`) the way bash does.
///
/// Without this, the parser's token differs from the argv word the program
/// receives, and because `normalize_path_value` maps `\` to `/` the leftover
/// backslash becomes a PATH SEPARATOR — so `cat $'~/.aws/cred\x65ntials'` files
/// `cat:~/.aws/cred/x65ntials` and the `credentials` component disappears from
/// `program_arg_path_components_normalized` entirely. That defeats allowlist and
/// denylist predicates alike, since it corrupts the tokenization rather than the
/// comparison.
///
/// Decodes into BYTES, not chars. `\xHH` and octal `\nnn` name a raw byte, and
/// two of them can jointly form one UTF-8 character: bash renders
/// `$'caf\xc3\xa9'` as `café`, which a char-wise decoder mangles into two
/// Latin-1 characters. Bytes that do not form valid UTF-8 at the end (a lone
/// `$'\xff'`) become U+FFFD via `from_utf8_lossy` — not byte-faithful to bash,
/// but the enforcement-relevant property is that the backslash is gone, so flag
/// names, allowlist membership and path components resolve.
///
/// An escape we cannot decode keeps BOTH characters, per bash's rule for
/// unrecognized forms inside `$'...'` (matching [`unescape_double_quoted`], not
/// [`unescape_unquoted_word`], which drops the backslash before anything). This
/// is load-bearing in two ways: the fallback is per-ESCAPE rather than
/// per-token, so one undecodable byte cannot revert a whole word and reopen the
/// bypass; and the surviving backslash keeps
/// `egress_parse::wget_directive_is_unreadable` firing on exactly the residue
/// this function declined.
fn unescape_ansi_c(text: &str) -> String {
    let src = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(src.len());
    let mut i = 0;
    while i < src.len() {
        if src[i] != b'\\' {
            out.push(src[i]);
            i += 1;
            continue;
        }
        let Some(&selector) = src.get(i + 1) else {
            // Trailing lone backslash: nothing to escape.
            out.push(b'\\');
            i += 1;
            continue;
        };
        let verbatim = |out: &mut Vec<u8>| {
            out.push(b'\\');
            out.push(selector);
        };
        i += 2;
        match selector {
            b'a' => out.push(0x07),
            b'b' => out.push(0x08),
            b'e' | b'E' => out.push(0x1b),
            b'f' => out.push(0x0c),
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'v' => out.push(0x0b),
            b'\\' | b'\'' | b'"' | b'?' => out.push(selector),
            // `\xHH`: 1-2 hex digits naming a raw byte.
            b'x' => {
                let (value, digits) = take_hex(src, &mut i, 2);
                if digits == 0 {
                    verbatim(&mut out);
                } else {
                    out.push(value as u8);
                }
            }
            // `\uHHHH` / `\UHHHHHHHH`: a code point, encoded as UTF-8.
            b'u' | b'U' => {
                let max = if selector == b'u' { 4 } else { 8 };
                let start = i;
                let (value, digits) = take_hex(src, &mut i, max);
                match char::from_u32(value).filter(|_| digits > 0) {
                    Some(ch) => {
                        let mut buf = [0u8; 4];
                        out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                    }
                    // Zero digits, or a lone surrogate that is not a `char`.
                    // Emit the whole escape verbatim rather than guessing.
                    None => {
                        verbatim(&mut out);
                        out.extend_from_slice(&src[start..i]);
                    }
                }
            }
            // `\nnn`: 1-3 octal digits, truncated to a byte as bash does.
            b'0'..=b'7' => {
                let mut value = u32::from(selector - b'0');
                let mut digits = 1;
                while digits < 3 {
                    let Some(d) = src.get(i).and_then(|c| (*c as char).to_digit(8)) else {
                        break;
                    };
                    value = value * 8 + d;
                    i += 1;
                    digits += 1;
                }
                out.push(value as u8);
            }
            // `\cX`: the control character for X. Bash's rule is
            // `x == '?' ? 0x7f : (x & 0x1f)`.
            //
            // Masking is NOT interchangeable with the uppercase-then-XOR-0x40
            // spelling. They agree on letters, `@`, `[`-`_` and `?`, but diverge
            // across 0x20-0x3f, and the divergence is a fail-OPEN: bash renders
            // `\c*` as 0x0a, so `scp -o $'BatchMode=yes\c*ProxyCommand=evil'`
            // reaches real ssh as two directives, while XOR yields a printable
            // `j`, `ssh_option_is_unreadable` sees no control character, and
            // `apply_ssh_option` reads the benign name `BatchMode` and resolves.
            // Any deviation from bash here re-creates the exact mismatch this
            // function exists to remove.
            b'c' => match src.get(i) {
                Some(&x) => {
                    out.push(if x == b'?' { 0x7f } else { x & 0x1f });
                    i += 1;
                }
                None => verbatim(&mut out),
            },
            _ => verbatim(&mut out),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(cmd: &str) -> ShellParse {
        analyze_shell_command(cmd)
    }

    fn progs(parse: &ShellParse) -> Vec<&str> {
        parse.programs.iter().map(String::as_str).collect()
    }

    #[test]
    fn simple_command_extracts_program_and_arg() {
        let r = p("rm file.txt");
        assert!(r.ok);
        assert_eq!(progs(&r), vec!["rm"]);
        assert!(r.program_args.contains("rm:file.txt"));
    }

    #[test]
    fn absolute_path_and_case_normalize_to_lowercase_basename() {
        assert_eq!(progs(&p("/bin/RM x")), vec!["rm"]);
        assert_eq!(progs(&p("Rm x")), vec!["rm"]);
    }

    #[test]
    fn shell_backslash_escapes_are_removed_before_matching() {
        let r = p(r"r\m -r\f /");
        assert!(r.ok);
        assert_eq!(progs(&r), vec!["rm"]);
        assert!(r.program_flags.contains("rm:-rf"));
        assert!(r.program_flags.contains("rm:-r"));
        assert!(r.program_flags.contains("rm:-f"));
        assert!(r.program_args.contains("rm:/"));
    }

    #[test]
    fn bundled_short_cluster_kept_raw_and_split() {
        let r = p("rm -rf /");
        assert!(r.program_flags.contains("rm:-rf"));
        assert!(r.program_flags.contains("rm:-r"));
        assert!(r.program_flags.contains("rm:-f"));
        assert!(r.program_args.contains("rm:/"));
    }

    #[test]
    fn separate_short_flags() {
        let r = p("rm -r -f /");
        assert!(r.program_flags.contains("rm:-r"));
        assert!(r.program_flags.contains("rm:-f"));
    }

    #[test]
    fn reordered_cluster_splits_to_same_singletons() {
        let r = p("rm -fr /");
        assert!(r.program_flags.contains("rm:-fr"));
        assert!(r.program_flags.contains("rm:-f"));
        assert!(r.program_flags.contains("rm:-r"));
    }

    #[test]
    fn long_flags_and_equals_value() {
        let r = p("git push --force");
        assert!(r.program_flags.contains("git:--force"));
        assert!(r.program_args.contains("git:push"));

        let r = p("git push --force-with-lease=main");
        assert!(r.program_flags.contains("git:--force-with-lease"));
    }

    #[test]
    fn double_dash_terminator_makes_rest_positional() {
        let r = p("rm -- -rf");
        assert!(r.program_args.contains("rm:-rf"));
        assert!(r.program_flags.is_empty());
    }

    #[test]
    fn non_alphabetic_short_flags_stay_raw_only() {
        let r = p("gcc -O2 -I/usr a.c");
        assert!(r.program_flags.contains("gcc:-O2"));
        assert!(r.program_flags.contains("gcc:-I/usr"));
        assert!(!r.program_flags.contains("gcc:-O"));
        assert!(!r.program_flags.contains("gcc:-I"));
        assert!(r.program_args.contains("gcc:a.c"));
    }

    #[test]
    fn and_chain_extracts_all_programs() {
        let r = p("cd /tmp && rm -rf x");
        assert_eq!(progs(&r), vec!["cd", "rm"]);
    }

    #[test]
    fn pipeline_sets_flag_and_extracts_both_sides() {
        let r = p("cat f | grep x");
        assert!(r.has_pipeline);
        assert_eq!(progs(&r), vec!["cat", "grep"]);
    }

    #[test]
    fn substitution_in_command_position_is_dynamic_and_mined() {
        let r = p("$(which rm) -rf /");
        assert!(r.has_dynamic_command);
        assert!(r.has_command_substitution);
        assert!(r.programs.contains("which"));
        assert!(r.program_args.contains("which:rm"));
        // No program scope for -rf: the outer command name is dynamic.
        assert!(!r.program_flags.iter().any(|f| f.ends_with(":-rf")));
    }

    #[test]
    fn substitution_in_arg_position_extracts_inner_command() {
        let r = p("echo $(rm -rf /)");
        assert!(r.has_command_substitution);
        assert_eq!(progs(&r), vec!["echo", "rm"]);
        assert!(r.program_flags.contains("rm:-r"));
        assert!(r.program_flags.contains("rm:-f"));
    }

    #[test]
    fn process_substitution_extracts_inner_commands() {
        let r = p("diff <(ls) <(pwd)");
        assert!(r.has_command_substitution);
        assert_eq!(progs(&r), vec!["diff", "ls", "pwd"]);
    }

    #[test]
    fn subshell_extracts_inner_command() {
        let r = p("(rm -rf /)");
        assert_eq!(progs(&r), vec!["rm"]);
        assert!(r.program_flags.contains("rm:-r"));
        assert!(r.program_flags.contains("rm:-f"));
    }

    #[test]
    fn bash_dash_c_recurses_into_script() {
        let r = p("bash -c \"rm -rf /\"");
        assert!(r.programs.contains("bash"));
        assert!(r.programs.contains("rm"));
        assert!(r.program_flags.contains("bash:-c"));
        assert!(r.program_flags.contains("rm:-r"));
        assert!(r.program_flags.contains("rm:-f"));
        // The script is decomposed under `rm`, never filed as a literal
        // positional of the shell.
        assert!(!r.program_args.contains("bash:rm -rf /"));
        assert!(r.program_args.contains("rm:/"));
    }

    #[test]
    fn eval_joins_literal_args_and_recurses() {
        let r = p("eval \"rm -rf /\"");
        assert!(r.programs.contains("eval"));
        assert!(r.programs.contains("rm"));
        assert!(r.program_flags.contains("rm:-r"));

        let r = p("eval rm -rf /");
        assert!(r.programs.contains("rm"));
        assert!(r.program_flags.contains("rm:-f"));
        assert!(r.program_args.contains("rm:/"));
    }

    #[test]
    fn reparse_depth_cap_marks_parse_incomplete() {
        let r = p("eval eval eval eval eval rm -rf /");
        assert!(!r.ok);
    }

    #[test]
    fn sudo_peel_scopes_flags_to_nested_program() {
        let r = p("sudo rm -rf /");
        assert_eq!(progs(&r), vec!["rm", "sudo"]);
        assert!(r.program_flags.contains("rm:-r"));
        assert!(r.program_flags.contains("rm:-f"));
        assert!(!r.program_flags.contains("sudo:-r"));
        assert!(r.program_args.contains("rm:/"));
    }

    #[test]
    fn sudo_value_flag_consumes_user_not_as_program() {
        let r = p("sudo -u alice rm x");
        assert_eq!(progs(&r), vec!["rm", "sudo"]);
        assert!(r.program_flags.contains("sudo:-u"));
        assert!(!r.programs.contains("alice"));
        assert!(r.program_args.contains("rm:x"));
    }

    #[test]
    fn sudo_long_value_flag_consumes_user_not_as_program() {
        let r = p("sudo --user alice rm -rf /");
        assert_eq!(progs(&r), vec!["rm", "sudo"]);
        assert!(r.program_flags.contains("sudo:--user"));
        assert!(!r.programs.contains("alice"));
        assert!(r.program_flags.contains("rm:-r"));
        assert!(r.program_flags.contains("rm:-f"));
    }

    #[test]
    fn env_peel_skips_assignments() {
        let r = p("env FOO=bar rm -rf /");
        assert_eq!(progs(&r), vec!["env", "rm"]);
        assert!(r.program_flags.contains("rm:-r"));
        assert!(r.program_flags.contains("rm:-f"));
    }

    #[test]
    fn env_long_chdir_consumes_dir_not_as_program() {
        let r = p("env --chdir /tmp rm -rf /");
        assert_eq!(progs(&r), vec!["env", "rm"]);
        assert!(r.program_flags.contains("env:--chdir"));
        assert!(!r.programs.contains("tmp"));
        assert!(r.program_flags.contains("rm:-r"));
        assert!(r.program_flags.contains("rm:-f"));
    }

    #[test]
    fn timeout_peel_skips_duration() {
        let r = p("timeout 5 rm -rf /");
        assert_eq!(progs(&r), vec!["rm", "timeout"]);
        assert!(!r.program_args.contains("rm:5"));
        assert!(r.program_args.contains("timeout:5"));
    }

    #[test]
    fn xargs_peel_extracts_nested_program() {
        let r = p("xargs rm -rf");
        assert_eq!(progs(&r), vec!["rm", "xargs"]);
        assert!(r.program_flags.contains("rm:-r"));
        assert!(r.program_flags.contains("rm:-f"));
    }

    #[test]
    fn nested_wrappers_peel_repeatedly() {
        let r = p("sudo env FOO=1 rm x");
        assert_eq!(progs(&r), vec!["env", "rm", "sudo"]);
        assert!(r.program_args.contains("rm:x"));
    }

    #[test]
    fn deep_wrapper_chain_does_not_overflow() {
        // Regression: a long flat wrapper chain parses as ONE command node, so
        // peel_wrapper <-> classify_invocation recursion (which bypasses the
        // visit() depth guard) must be bounded by MAX_TREE_DEPTH or it aborts
        // the process on stack overflow. Completing this call is the assertion.
        let cmd = format!("{}rm", "sudo ".repeat(MAX_TREE_DEPTH * 4));
        let r = p(&cmd);
        assert!(!r.ok, "deep wrapper chain should mark the parse incomplete");
    }

    #[test]
    fn shallow_wrapper_chain_still_resolves_nested_program() {
        // The depth bound must not regress ordinary nesting.
        let r = p("sudo sudo rm -rf /");
        assert!(r.ok);
        assert!(r.programs.contains("rm"));
        assert!(r.program_flags.contains("rm:-r"));
    }

    #[test]
    fn dynamic_nested_name_does_not_scope_flags_to_wrapper() {
        // Regression: a dynamic nested-command name must leave the following
        // flags/args UNSCOPED, not attribute them to the wrapper.
        let r = p("sudo $TOOL -rf /");
        assert!(r.has_dynamic_command);
        assert!(r.programs.contains("sudo"));
        assert!(!r.program_flags.contains("sudo:-r"));
        assert!(!r.program_flags.contains("sudo:-rf"));
        assert!(!r.program_args.contains("sudo:/"));
    }

    #[test]
    fn dynamic_nested_name_with_long_flag_promotes_no_program() {
        let r = p("env $CMD --force file");
        assert!(r.has_dynamic_command);
        assert_eq!(progs(&r), vec!["env"]);
        assert!(!r.program_flags.contains("env:--force"));
        assert!(!r.programs.contains("file"));
    }

    #[test]
    fn trailing_value_flag_finds_no_nested_program() {
        // `sudo -u` with no following token: a contract-conforming degrade —
        // no nested program, no panic (args.get guards the OOB).
        let r = p("sudo -u");
        assert!(r.program_flags.contains("sudo:-u"));
        assert_eq!(progs(&r), vec!["sudo"]);
    }

    #[test]
    fn number_base_with_substitution_is_mined_not_filed_literally() {
        // Regression: `<base>#$(...)` parses as a `number` node wrapping a
        // command_substitution; it must be treated as dynamic so the inner
        // command is extracted and the substitution flag set.
        let r = p("echo 64#$(rm -rf /)");
        assert!(r.has_command_substitution);
        assert!(r.programs.contains("rm"));
        assert!(!r.program_args.contains("echo:64#$(rm -rf /)"));
    }

    #[test]
    fn plain_number_arg_is_literal() {
        let r = p("sleep 5");
        assert!(r.program_args.contains("sleep:5"));
    }

    #[test]
    fn literal_dollar_in_double_quotes_is_preserved() {
        // Regression: a literal `$` is an anonymous token; the string arm must
        // keep it rather than concatenate only string_content children.
        let r = p("echo \"price$\"");
        assert!(r.program_args.contains("echo:price$"));
    }

    #[test]
    fn double_quote_escapes_are_removed() {
        let r = p("echo \"a\\\"b\\\\c\"");
        assert!(r.program_args.contains("echo:a\"b\\c"));
    }

    // ── ANSI-C (`$'...'`) escape decoding ──

    /// The decoder in isolation, across bash's escape vocabulary. Getting a
    /// spelling wrong here silently re-creates the bypass in a new form, so each
    /// family is pinned rather than sampled.
    #[test]
    fn ansi_c_escapes_decode_like_bash() {
        for (input, want) in [
            // C single-character escapes.
            (r"a\nb", "a\nb"),
            (r"a\tb", "a\tb"),
            (r"a\rb", "a\rb"),
            (r"a\\b", r"a\b"),
            (r"a\'b", "a'b"),
            (r#"a\"b"#, "a\"b"),
            (r"a\ab", "a\u{07}b"),
            (r"a\bb", "a\u{08}b"),
            (r"a\eb", "a\u{1b}b"),
            (r"a\Eb", "a\u{1b}b"),
            (r"a\fb", "a\u{0c}b"),
            (r"a\vb", "a\u{0b}b"),
            (r"a\?b", "a?b"),
            // Hex. Bash accepts ONE or two digits, so a short form followed by a
            // non-hex character must not swallow it.
            (r"cred\x65ntials", "credentials"),
            (r"a\x41b", "aAb"),
            (r"a\xAz", "a\nz"),
            // Octal, including the `\0` NUL spelling and bash's mod-256 wrap.
            (r"http\137proxy", "http_proxy"),
            (r"a\101b", "aAb"),
            (r"a\0b", "a\0b"),
            // Unicode, full and short width.
            (r"a\u0041b", "aAb"),
            (r"a\u41z", "aAz"),
            (r"a\U00000041b", "aAb"),
            // Control forms. Bash masks with 0x1f, special-casing `?`. The rows
            // outside A-Z are the ones that distinguish masking from an
            // uppercase-then-XOR-0x40 spelling, which agrees on letters and then
            // fails open across 0x20-0x3f — see the `\cX` arm.
            (r"a\cAb", "a\u{01}b"),
            (r"a\cab", "a\u{01}b"),
            (r"a\cJb", "a\nb"),
            (r"a\c?b", "a\u{7f}b"),
            (r"a\c\b", "a\u{1c}b"),
            (r"a\c*b", "a\nb"),
            (r"a\c0b", "a\u{10}b"),
            // Multi-byte: two high hex escapes jointly form ONE UTF-8 character.
            // A char-wise decoder produces "cafÃ©" here instead.
            (r"caf\xc3\xa9", "café"),
            // Undecodable forms keep BOTH characters, per bash's `$'\q'` rule.
            // The surviving backslash is what keeps
            // `egress_parse::wget_directive_is_unreadable` firing on the residue.
            (r"a\qb", r"a\qb"),
            (r"a\x", r"a\x"),
            (r"a\", r"a\"),
            (r"a\uD800b", r"a\uD800b"),
            // A lone high byte is not valid UTF-8 and lands as U+FFFD — but note
            // the ASCII part around it still decodes (see the anti-reversion test
            // below, which is the security-relevant half of this).
            (r"a\xffb", "a\u{fffd}b"),
        ] {
            assert_eq!(unescape_ansi_c(input), want, "input: {input:?}");
        }
    }

    /// `normalize_path_value` maps `\` to `/`, so an undecoded escape used to
    /// become a path separator and shatter the normalized component view.
    #[test]
    fn ansi_c_escape_no_longer_shatters_the_normalized_path_view() {
        let r = p(r"cat $'~/.aws/cred\x65ntials'");
        assert!(r.program_args.contains("cat:~/.aws/credentials"));
        assert!(r.program_args_normalized.contains("cat:~/.aws/credentials"));
        assert!(
            r.program_arg_path_components_normalized
                .contains("cat:credentials")
        );
        // The mangled spellings must be gone, not merely joined by the right one.
        assert!(
            !r.program_arg_path_components_normalized
                .contains("cat:x65ntials")
        );
        assert!(
            !r.program_args_normalized
                .contains("cat:~/.aws/cred/x65ntials")
        );
    }

    /// Escaping a character in a directory component must remain matchable.
    #[test]
    fn ansi_c_escaped_path_component_is_matchable() {
        let r = p(r"cat $'~/\x2eaws/credentials'");
        assert!(
            r.program_arg_path_components_normalized
                .contains("cat:.aws")
        );
        assert!(
            !r.program_arg_path_components_normalized
                .contains("cat:x2eaws")
        );
    }

    /// B3: `normalize_program` takes a basename by splitting on `['/', '\\']`, so
    /// an undecoded escape in the COMMAND word used to truncate the program name
    /// to the escape's tail — `$'c\x75rl'` filed as `x75rl`. That dropped the
    /// invocation out of `programs` (~419 refs) AND out of
    /// `is_egress_program`, so the entire egress record went missing rather than
    /// merely being mislabelled.
    #[test]
    fn ansi_c_escaped_program_name_resolves() {
        let r = p(r"$'c\x75rl' https://allowed.example/x");
        assert!(r.ok, "command word should still parse");
        assert_eq!(progs(&r), vec!["curl"]);
        assert!(!r.has_dynamic_command);
    }

    /// The same decoding applies to normalized program flags.
    #[test]
    fn ansi_c_escaped_flag_resolves() {
        let r = p(r"rm $'-r\x66' /tmp/x");
        assert!(r.program_flags.contains("rm:-rf"));
        assert!(r.program_flags_normalized.contains("rm:-rf"));
    }

    /// The attacker's next move once whole-token escaping is fixed: escape only
    /// a FRAGMENT, so the `$'...'` node is one child of a `concatenation`.
    #[test]
    fn ansi_c_fragment_inside_a_concatenation_decodes() {
        let r = p(r"cat ~/.aws/cred$'\x65'ntials");
        assert!(r.program_args.contains("cat:~/.aws/credentials"));
        assert!(
            r.program_arg_path_components_normalized
                .contains("cat:credentials")
        );
    }

    /// Node extent, not escape spelling: `\'` is legal inside `$'...'`, so the
    /// naive `strip_suffix('\'')` must still cut at the real closing quote.
    #[test]
    fn ansi_c_embedded_quote_and_empty_body() {
        let r = p(r"echo $'a\'b'");
        assert!(r.program_args.contains("echo:a'b"));
        let r = p("echo $''");
        assert!(r.program_args.contains("echo:"));
    }

    /// Idempotence: `$'\\'` is ONE backslash of content. It must reach
    /// `normalize_path_value` and be mapped to `/` exactly once — not re-read as
    /// an escape, and not left doubled.
    #[test]
    fn decoded_backslash_is_content_not_re_escaped() {
        let r = p(r"cat $'a\\b'");
        assert!(r.program_args.contains(r"cat:a\b"));
        assert!(r.program_args_normalized.contains("cat:a/b"));
    }

    /// Decoding introduces real whitespace, but `$'...'` never word-splits, so
    /// the result must remain one argument.
    #[test]
    fn decoded_whitespace_does_not_split_the_argument() {
        let r = p(r"curl -H $'X-Trace:\x20abc' https://allowed.example/x");
        assert!(r.program_args.contains("curl:X-Trace: abc"));
        assert!(r.program_args.contains("curl:https://allowed.example/x"));
    }

    /// Anti-reversion: the undecodable fallback is per-ESCAPE, not per-token. If
    /// one bad byte reverted the whole word, appending `\xff` to any payload
    /// would reopen B1 with a single character.
    #[test]
    fn one_undecodable_escape_does_not_revert_the_whole_token() {
        let r = p(r"cat $'~/.aws/cred\x65ntials\xff'");
        assert!(
            r.program_arg_path_components_normalized
                .contains("cat:credentials\u{fffd}")
        );
        // The ASCII part decoded, so no stray `/` component appeared.
        assert!(
            !r.program_arg_path_components_normalized
                .contains("cat:x65ntials")
        );

        let r = p(r"cat $'~/.aws/cred\x65ntials\q'");
        assert!(r.program_args.contains(r"cat:~/.aws/credentials\q"));
    }

    #[test]
    fn assignment_prefix_is_not_a_program() {
        let r = p("FOO=bar rm x");
        assert_eq!(progs(&r), vec!["rm"]);
        assert!(r.program_args.contains("rm:x"));
    }

    #[test]
    fn assignment_prefix_rhs_substitution_is_mined() {
        let r = p("FOO=$(rm -rf /) echo hi");
        assert!(r.has_command_substitution);
        assert!(r.programs.contains("rm"));
        assert!(r.programs.contains("echo"));
    }

    #[test]
    fn dynamic_command_name_emits_no_program_or_flags() {
        let r = p("$TOOL --force");
        assert!(r.has_dynamic_command);
        assert!(r.programs.is_empty());
        assert!(r.program_flags.is_empty());
    }

    #[test]
    fn unterminated_quote_degrades_to_not_ok() {
        let r = p("rm -rf \"unterminated");
        assert!(!r.ok);
    }

    #[test]
    fn redirection_sets_flag() {
        let r = p("cat f > out.txt");
        assert!(r.has_redirection);
        assert_eq!(progs(&r), vec!["cat"]);
        assert!(r.program_args.contains("cat:f"));
    }

    #[test]
    fn heredoc_sets_redirection_flag() {
        let r = p("cat <<EOF\nhi\nEOF");
        assert!(r.has_redirection);
        assert_eq!(progs(&r), vec!["cat"]);
    }

    #[test]
    fn herestring_sets_redirection_flag() {
        let r = p("grep x <<< hi");
        assert!(r.has_redirection);
        assert!(r.programs.contains("grep"));
    }

    #[test]
    fn negated_command_extracts_program() {
        let r = p("! rm x");
        assert!(r.programs.contains("rm"));
    }

    #[test]
    fn test_command_parses_without_extraction() {
        let r = p("[[ -f x ]]");
        assert!(r.ok);
        assert!(r.programs.is_empty());
    }

    #[test]
    fn empty_command_yields_empty_ok_parse() {
        let r = p("");
        assert!(r.ok);
        assert!(r.programs.is_empty());
        assert!(r.program_flags.is_empty());
        assert!(r.program_args.is_empty());
        assert!(!r.has_dynamic_command);
        assert!(!r.has_command_substitution);
        assert!(!r.has_pipeline);
        assert!(!r.has_redirection);
    }

    #[test]
    fn oversized_command_skips_parsing() {
        let big = format!("echo {}", "a".repeat(MAX_COMMAND_BYTES));
        let r = p(&big);
        assert!(!r.ok);
        assert!(r.programs.is_empty());
    }

    #[test]
    fn to_cedar_json_shape_matches_schema() {
        let json = p("sudo rm -rf /").to_cedar_json();
        assert_eq!(json["ok"], true);
        let programs: Vec<&str> = json["programs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(programs, vec!["rm", "sudo"]);
        let flags: Vec<&str> = json["program_flags"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(flags.contains(&"rm:-r"));
        assert!(flags.contains(&"rm:-rf"));
        let normalized_flags: Vec<&str> = json["program_flags_normalized"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(normalized_flags.contains(&"rm:-r"));
        assert_eq!(json["has_dynamic_command"], false);
        assert_eq!(json["has_pipeline"], false);
        assert_eq!(json["has_command_substitution"], false);
        assert_eq!(json["has_redirection"], false);
    }

    /// Windows process-kill tokenization that pack self-defense rules depend
    /// on: the target process name must surface as a positional
    /// `program_args` value so `taskkill:sondera.exe` / `stop-process:sondera`
    /// conjuncts match.
    /// tree-sitter-bash treats Windows `/FLAG` tokens as positionals (they are
    /// not `-`-prefixed), and non-wrapper programs do not consume flag values,
    /// so a PowerShell `-Name <target>` files `<target>` as a positional too.
    #[test]
    fn windows_process_kill_targets_surface_as_program_args() {
        // cmd.exe-style taskkill: `/F` and `/IM` are positionals, and the image
        // name is a positional — the conjunct target `taskkill:sondera.exe`.
        let r = p("taskkill /F /IM sondera.exe");
        assert!(r.ok);
        assert!(r.programs.contains("taskkill"));
        assert!(r.program_args.contains("taskkill:sondera.exe"));
        assert!(r.program_args.contains("taskkill:/IM"));
        assert!(r.program_args_normalized.contains("taskkill:sondera.exe"));
        assert!(r.program_args_normalized.contains("taskkill:/im"));

        // PowerShell Stop-Process: `-Name` value files as a positional target,
        // matching the pack's `stop-process:sondera` conjunct.
        let r = p("Stop-Process -Name sondera");
        assert!(r.ok);
        assert!(r.programs.contains("stop-process"));
        assert!(r.program_args.contains("stop-process:sondera"));
    }

    #[test]
    fn windows_program_paths_strip_basename_exe_and_case() {
        assert_eq!(
            normalize_program(r"C:\Windows\System32\PowerShell.EXE"),
            "powershell"
        );
        assert_eq!(normalize_program(r".\RM.exe"), "rm");
        assert_eq!(normalize_program(r".\foo.exe.exe"), "foo.exe");
        assert_eq!(
            normalize_program(r".\runner.executable"),
            "runner.executable"
        );
    }

    #[test]
    fn normalized_arg_companions_fold_case_separators_and_components() {
        let r = p(r#"cat 'C:\Users\Alice\.AWS\Credentials' backup.aws.json .awsome-config"#);
        assert!(r.ok);
        assert!(
            r.program_args
                .contains(r"cat:C:\Users\Alice\.AWS\Credentials")
        );
        assert!(
            r.program_args_normalized
                .contains("cat:c:/users/alice/.aws/credentials")
        );
        assert!(
            r.program_arg_path_components_normalized
                .contains("cat:.aws")
        );
        assert!(
            r.program_arg_path_components_normalized
                .contains("cat:backup.aws.json")
        );
        assert!(
            r.program_arg_path_components_normalized
                .contains("cat:.awsome-config")
        );
        assert!(
            !r.program_arg_path_components_normalized
                .contains("cat:awsome-config")
        );

        let r = p(r"cat C:\Users\Alice\.AWS\Credentials");
        assert!(r.ok);
        assert!(
            r.program_args_normalized
                .contains("cat:c:/users/alice/.aws/credentials")
        );
        assert!(
            r.program_arg_path_components_normalized
                .contains("cat:.aws")
        );

        let r = p(r"cat aws\file");
        assert!(r.ok);
        assert!(r.program_arg_path_components_normalized.contains("cat:aws"));
        assert!(
            r.program_arg_path_components_normalized
                .contains("cat:file")
        );

        let r = p(r"cat x\aws\file");
        assert!(r.ok);
        assert!(r.program_arg_path_components_normalized.contains("cat:x"));
        assert!(r.program_arg_path_components_normalized.contains("cat:aws"));
        assert!(
            r.program_arg_path_components_normalized
                .contains("cat:file")
        );

        let r = p(r"cat .aws\credentials");
        assert!(r.ok);
        assert!(
            r.program_args_normalized.contains("cat:.aws/credentials"),
            "raw relative Windows fallback should preserve the separator before Bash unescaping"
        );
        assert!(
            r.program_arg_path_components_normalized
                .contains("cat:.aws")
        );
        assert!(
            r.program_arg_path_components_normalized
                .contains("cat:credentials")
        );

        let r = p(r"cat .ssh\id_rsa");
        assert!(r.ok);
        assert!(
            r.program_arg_path_components_normalized
                .contains("cat:.ssh")
        );
        assert!(
            r.program_arg_path_components_normalized
                .contains("cat:id_rsa")
        );

        let r = p(r"cat x\.aws\credentials");
        assert!(r.ok);
        assert!(
            r.program_arg_path_components_normalized
                .contains("cat:.aws")
        );
        assert!(
            r.program_arg_path_components_normalized
                .contains("cat:credentials")
        );

        let r = p(r"cat _workspace\file");
        assert!(r.ok);
        assert!(
            r.program_arg_path_components_normalized
                .contains("cat:_workspace")
        );
        assert!(
            r.program_arg_path_components_normalized
                .contains("cat:file")
        );

        let r = p(r"cat \users\alice");
        assert!(r.ok);
        assert!(
            r.program_arg_path_components_normalized
                .contains("cat:users")
        );
        assert!(
            r.program_arg_path_components_normalized
                .contains("cat:alice")
        );

        let r = p(r"cat \.aws\*");
        assert!(r.ok);
        assert!(
            r.program_arg_path_components_normalized
                .contains("cat:.aws")
        );
        assert!(r.program_arg_path_components_normalized.contains("cat:*"));

        let r = p(r"cat \aws\*");
        assert!(r.ok);
        assert!(r.program_arg_path_components_normalized.contains("cat:aws"));
        assert!(r.program_arg_path_components_normalized.contains("cat:*"));

        let r = p(r"cat foo\*");
        assert!(r.ok);
        assert!(r.program_args_normalized.contains("cat:foo/*"));
        assert!(r.program_arg_path_components_normalized.contains("cat:foo"));
        assert!(r.program_arg_path_components_normalized.contains("cat:*"));

        let r = p(r"cat foo\*.json");
        assert!(r.ok);
        assert!(r.program_args_normalized.contains("cat:foo/*.json"));
        assert!(r.program_arg_path_components_normalized.contains("cat:foo"));
        assert!(
            r.program_arg_path_components_normalized
                .contains("cat:*.json")
        );

        let r = p(r"cat foo\?.json");
        assert!(r.ok);
        assert!(r.program_args_normalized.contains("cat:foo/?.json"));
        assert!(r.program_arg_path_components_normalized.contains("cat:foo"));
        assert!(
            r.program_arg_path_components_normalized
                .contains("cat:?.json")
        );

        let r = p(r"cat x\aws\*");
        assert!(r.ok);
        assert!(r.program_arg_path_components_normalized.contains("cat:x"));
        assert!(r.program_arg_path_components_normalized.contains("cat:aws"));
        assert!(r.program_arg_path_components_normalized.contains("cat:*"));

        let r = p(r"cat backup\.aws\.json");
        assert!(r.ok);
        assert!(
            r.program_args_normalized.contains("cat:backup.aws.json"),
            "ordinary shell escapes should still use shell-literal normalization"
        );
        assert!(
            !r.program_arg_path_components_normalized
                .contains("cat:.aws"),
            "escaped dots in one filename must not be reinterpreted as Windows path separators"
        );

        let r = p(r"cat foo\ bar");
        assert!(r.ok);
        assert!(r.program_args_normalized.contains("cat:foo bar"));
        assert!(
            !r.program_arg_path_components_normalized.contains("cat:foo"),
            "escaped spaces in one filename must not be reinterpreted as Windows path separators"
        );
    }
}
