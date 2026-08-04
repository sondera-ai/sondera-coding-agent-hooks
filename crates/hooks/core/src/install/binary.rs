//! Locate the umbrella `sondera` binary for embedding in hook configs.
//!
//! The path returned here gets baked into provider config files (e.g.
//! `~/.claude/settings.json`) as an absolute path, so we prefer stable
//! system-wide locations over transient user-bin entries and `which`
//! lookups. PATH lookup is a last resort because the Python SDK ships a
//! `sondera` entrypoint that can shadow the Rust binary on user shells.
//!
//! # Making the unquoted-path bug impossible by construction
//!
//! The unquoted-path bug was a raw filesystem path (`\\?\C:\Program Files\...`) reaching a
//! provider's command field unquoted, so the consuming shell split it at the
//! space and never invoked sondera. The fix is structural, not a patch at each
//! call site:
//!
//! * [`find_sondera_binary`] returns a [`ResolvedBinary`], **not** a
//!   [`PathBuf`]. `ResolvedBinary` intentionally implements neither `Display`,
//!   `AsRef<str>`, `AsRef<Path>`, nor `Deref<Target = Path>`, so
//!   `format!("{binary} …")` — the exact shape that caused it — does not
//!   compile.
//! * The only way to turn a resolved binary into hook-command text is
//!   [`ResolvedBinary::render`], which strips the Windows verbatim prefix and
//!   quotes for the specific shell that consumes the command. A new provider
//!   physically cannot skip that step.
//! * Spawning the binary as a subprocess (not through a shell) uses
//!   [`ResolvedBinary::as_execution_path`]; human-facing diagnostics use
//!   [`ResolvedBinary::display_path`]. Both are named so their non-command
//!   purpose is obvious at the call site.

use std::env;
use std::path::{Path, PathBuf};

use crate::error::{HookResultExt as _, Result};

const BINARY_NAME: &str = "sondera";

/// Canonicalize `path`, preferring an ordinary Windows path over the
/// extended-length verbatim form.
///
/// `std::fs::canonicalize` returns a verbatim/extended-length path (`\\?\C:\…`)
/// on Windows; left in place that prefix leaks into every emitted hook command
/// and, being non-canonical and unquoted, splits at the first space in
/// `Program Files`. `dunce::canonicalize` returns the ordinary form
/// whenever it is safe (i.e. except for genuinely long or UNC paths), removing
/// the prefix at its source. [`ResolvedBinary`] strips any residual prefix as a
/// second line of defense.
fn canonical_or_original(path: PathBuf) -> PathBuf {
    dunce::canonicalize(&path).unwrap_or(path)
}

/// Strip a *safe* Windows verbatim (`\\?\`) prefix from a rendered path.
///
/// Only extended-length **disk** paths (`\\?\C:\...`) are simplified back to
/// their ordinary form (`C:\...`). Verbatim UNC paths (`\\?\UNC\server\share`)
/// are returned unchanged: dropping their prefix would change the path's
/// meaning. A no-op on any string without the prefix, so it is safe to call on
/// every platform (the prefix cannot occur in a Unix path).
fn strip_verbatim_prefix(rendered: &str) -> &str {
    let Some(rest) = rendered.strip_prefix(r"\\?\") else {
        return rendered;
    };
    let bytes = rest.as_bytes();
    let is_disk = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if is_disk { rest } else { rendered }
}

fn validate(path: PathBuf) -> Option<PathBuf> {
    if path.is_file() {
        Some(canonical_or_original(path))
    } else {
        None
    }
}

fn is_sondera_exe(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|n| n.to_str()),
        Some(BINARY_NAME) | Some("sondera.exe")
    )
}

/// A resolved `sondera` executable, guaranteed free of the Windows verbatim
/// (`\\?\`) prefix.
///
/// The only constructors are [`find_sondera_binary`] (discovery) and
/// [`ResolvedBinary::from_exe_path`] (a caller that already holds the exact
/// executable path, e.g. the running daemon's own `current_exe`). Both
/// normalize the path on the way in.
///
/// This type deliberately does **not** implement `Display`, `AsRef<str>`,
/// `AsRef<Path>`, or `Deref<Target = Path>`. The only way to a hook-command
/// string is [`render`](ResolvedBinary::render), which quotes for the target
/// shell — so a raw path can never be formatted straight into a command field.
/// Subprocess spawning uses [`as_execution_path`](Self::as_execution_path)
/// and diagnostics use [`display_path`](Self::display_path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedBinary(PathBuf);

impl ResolvedBinary {
    /// Wrap an already-known executable path, normalizing away any Windows
    /// verbatim prefix. Prefer [`find_sondera_binary`] for discovery; use this
    /// only when the caller already holds the exact binary path (e.g. a daemon
    /// pointing at its own `current_exe`).
    pub fn from_exe_path(path: PathBuf) -> Self {
        match path.to_str() {
            Some(rendered) => {
                let simplified = strip_verbatim_prefix(rendered);
                if simplified.len() != rendered.len() {
                    Self(PathBuf::from(simplified))
                } else {
                    Self(path)
                }
            }
            // Non-UTF-8 paths never carry the ASCII `\\?\` prefix; pass through.
            None => Self(path),
        }
    }

    /// The executable path for spawning the binary as a subprocess (via
    /// [`std::process::Command`]). Safe because a process launch takes the whole
    /// path as a single argument — there is no shell to split it. **Never** use
    /// this to build a shell command string; use [`render`](Self::render).
    pub fn as_execution_path(&self) -> &Path {
        &self.0
    }

    /// The path for human-facing diagnostics (logs, error messages). Never
    /// executed and never embedded in a command field.
    pub fn display_path(&self) -> std::path::Display<'_> {
        self.0.display()
    }

    /// Render the executable portion of a hook command for `shell`.
    ///
    /// This is the single seam where a resolved binary becomes command text.
    /// See [`CommandShell`] for the per-target contract. The verbatim prefix is
    /// already gone by construction; rendering strips it again defensively so
    /// the function is correct for any `ResolvedBinary` regardless of how it was
    /// built.
    pub fn render(&self, shell: CommandShell) -> String {
        let path = self.0.as_path();
        // The `.exe`-bearing, prefix-stripped form both Windows shells need.
        // Computed lazily so the POSIX arm — which renders via `portable_str` —
        // never pays for it.
        let windows_exe = || {
            let rendered = path.to_string_lossy();
            with_exe(strip_verbatim_prefix(&rendered))
        };
        match shell {
            CommandShell::Posix => posix_quote(&portable_str(path)),
            CommandShell::WindowsCmd => windows_double_quote(&windows_exe()),
            CommandShell::PowerShell => format!("& {}", powershell_quote(&windows_exe())),
        }
    }
}

/// The shell contract a rendered hook command targets.
///
/// A provider config's command field is consumed differently per provider and
/// OS, so the executable must be rendered to match. Getting this wrong is what
/// caused the bug: an unquoted `C:\Program Files\...` path split on its space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandShell {
    /// A POSIX shell command line (`sh`/`bash`): Claude/Cursor/Gemini/Hermes and
    /// the VS Code / Copilot commands on Unix. Extension-less portable `sondera`,
    /// single-quoted only when the path carries shell-significant characters.
    Posix,
    /// A Windows command line (`cmd.exe` / VS Code `command` on Windows), where
    /// the first token is the program. `.exe` is retained and the path is
    /// double-quoted when it contains a space so the shell keeps it whole.
    WindowsCmd,
    /// A PowerShell *script* (Copilot's `powershell` field). A bare quoted path
    /// there is just a string literal, so the executable must be launched with
    /// the `&` call operator; `.exe` is retained and single-quoted when needed.
    PowerShell,
}

/// The portable, extension-less form of the binary path for a command string.
///
/// Hook commands written into provider config files are a stable, portable
/// contract: agent runtimes execute them through a shell (`sh`/`bash` on Unix;
/// `cmd`/PowerShell with PATHEXT resolution on Windows), so a bare `sondera`
/// resolves the same on every OS. The path baked in comes from
/// [`find_sondera_binary`], which prefers `std::env::current_exe()` — and that
/// names the running binary `sondera.exe` on Windows. Emitting the raw string
/// would leak the host's executable extension into a cross-platform contract:
/// installed commands and clap's inferred help usage would include `sondera.exe`.
/// Stripping a trailing `.exe` yields the stable `sondera` form. This is a
/// byte-identical no-op on Unix.
fn portable_str(path: &Path) -> String {
    let rendered = path.to_string_lossy();
    let rendered = strip_verbatim_prefix(&rendered);
    for suffix in [".exe", ".EXE"] {
        if let Some(stripped) = rendered.strip_suffix(suffix) {
            return stripped.to_owned();
        }
    }
    rendered.to_owned()
}

/// Ensure a Windows executable path keeps its `.exe` extension. A shell finds a
/// bare `sondera` via PATHEXT, but a process-boundary launch of an absolute path
/// resolves by exact name, so Windows commands must name `sondera.exe`.
fn with_exe(rendered: &str) -> String {
    if rendered.ends_with(".exe") || rendered.ends_with(".EXE") {
        rendered.to_owned()
    } else {
        format!("{rendered}.exe")
    }
}

/// POSIX single-quote a token, but only when it carries a shell-significant
/// character. Plain paths pass through unchanged so space-free commands keep
/// their historical bare form.
fn posix_quote(value: &str) -> String {
    if value.chars().any(is_posix_significant) {
        format!("'{}'", value.replace('\'', "'\\''"))
    } else {
        value.to_owned()
    }
}

fn is_posix_significant(ch: char) -> bool {
    ch.is_whitespace()
        || matches!(
            ch,
            '\'' | '"'
                | '\\'
                | '$'
                | '`'
                | '!'
                | '&'
                | ';'
                | '('
                | ')'
                | '<'
                | '>'
                | '|'
                | '*'
                | '?'
                | '['
                | ']'
                | '{'
                | '}'
                | '~'
                | '#'
        )
}

/// Double-quote a Windows command token when it contains whitespace so the shell
/// treats it as a single argument. `cmd.exe` has no in-quote escape for `"`; the
/// installed path is administrator-owned and never contains one.
fn windows_double_quote(value: &str) -> String {
    if value.chars().any(char::is_whitespace) {
        format!("\"{value}\"")
    } else {
        value.to_owned()
    }
}

/// PowerShell single-quote a token when it needs it. Single quotes are literal
/// in PowerShell; an embedded single quote is escaped by doubling it.
fn powershell_quote(value: &str) -> String {
    if value.chars().any(|ch| ch.is_whitespace() || ch == '\'') {
        format!("'{}'", value.replace('\'', "''"))
    } else {
        value.to_owned()
    }
}

/// Discovery order, most to least preferred:
/// 1. Current executable when invoked as `sondera <provider> install`.
/// 2. `/usr/local/bin/sondera` — stable macOS / common Linux install path.
/// 3. `/usr/bin/sondera` — distro-managed install.
/// 4. `~/.sondera/bin/sondera` — local dev / `make install-claude-local`.
/// 5. `~/.cargo/bin/sondera` — `cargo install` location.
/// 6. PATH lookup as a fallback (may resolve to the Python SDK wrapper).
pub fn find_sondera_binary() -> Result<ResolvedBinary> {
    if let Ok(exe) = env::current_exe()
        && is_sondera_exe(&exe)
        && let Some(p) = validate(exe)
    {
        return Ok(ResolvedBinary::from_exe_path(p));
    }

    for system in [
        PathBuf::from("/usr/local/bin/sondera"),
        PathBuf::from("/usr/bin/sondera"),
    ] {
        if let Some(p) = validate(system) {
            return Ok(ResolvedBinary::from_exe_path(p));
        }
    }

    if let Some(home) = dirs::home_dir() {
        for user in [
            home.join(".sondera").join("bin").join("sondera"),
            home.join(".cargo").join("bin").join("sondera"),
        ] {
            if let Some(p) = validate(user) {
                return Ok(ResolvedBinary::from_exe_path(p));
            }
        }
    }

    let from_path = which::which(BINARY_NAME).context(
        "Could not find a sondera binary. Install via `make install-claude` or ensure \
         sondera is on PATH.",
    )?;
    let validated = validate(from_path.clone()).with_context(|| {
        format!(
            "PATH lookup resolved sondera to '{}', but that path is not a file.",
            from_path.display()
        )
    })?;
    Ok(ResolvedBinary::from_exe_path(validated))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rb(path: &str) -> ResolvedBinary {
        ResolvedBinary::from_exe_path(PathBuf::from(path))
    }

    #[test]
    fn strip_verbatim_simplifies_disk_paths_only() {
        assert_eq!(
            strip_verbatim_prefix(r"\\?\C:\Program Files\Sondera\sondera.exe"),
            r"C:\Program Files\Sondera\sondera.exe"
        );
        // Lower-case drive letters are also disk paths.
        assert_eq!(
            strip_verbatim_prefix(r"\\?\d:\tools\sondera.exe"),
            r"d:\tools\sondera.exe"
        );
        // Verbatim UNC keeps its prefix — dropping it changes meaning.
        assert_eq!(
            strip_verbatim_prefix(r"\\?\UNC\server\share\sondera.exe"),
            r"\\?\UNC\server\share\sondera.exe"
        );
        // Ordinary paths (any platform) are untouched.
        assert_eq!(
            strip_verbatim_prefix("/usr/local/bin/sondera"),
            "/usr/local/bin/sondera"
        );
        assert_eq!(
            strip_verbatim_prefix(r"C:\Sondera\sondera.exe"),
            r"C:\Sondera\sondera.exe"
        );
    }

    #[test]
    fn from_exe_path_strips_verbatim_prefix() {
        let binary = rb(r"\\?\C:\Program Files\Sondera\sondera.exe");
        assert_eq!(
            binary.as_execution_path(),
            Path::new(r"C:\Program Files\Sondera\sondera.exe")
        );
    }

    #[test]
    fn posix_render_strips_verbatim_prefix_and_exe() {
        assert_eq!(
            rb(r"\\?\C:\Program Files\Sondera\sondera.exe").render(CommandShell::Posix),
            r"'C:\Program Files\Sondera\sondera'"
        );
    }

    #[test]
    fn windows_cmd_retains_exe_and_double_quotes_program_files() {
        assert_eq!(
            rb(r"\\?\C:\Program Files\Sondera\sondera.exe").render(CommandShell::WindowsCmd),
            r#""C:\Program Files\Sondera\sondera.exe""#
        );
    }

    #[test]
    fn windows_cmd_adds_exe_to_extension_less_path_without_quoting_when_space_free() {
        assert_eq!(
            rb(r"C:\Sondera\sondera").render(CommandShell::WindowsCmd),
            r"C:\Sondera\sondera.exe"
        );
    }

    #[test]
    fn powershell_uses_call_operator_and_single_quotes_program_files() {
        assert_eq!(
            rb(r"\\?\C:\Program Files\Sondera\sondera.exe").render(CommandShell::PowerShell),
            r"& 'C:\Program Files\Sondera\sondera.exe'"
        );
    }

    #[test]
    fn powershell_space_free_path_still_uses_call_operator_without_quotes() {
        assert_eq!(
            rb(r"C:\Sondera\sondera.exe").render(CommandShell::PowerShell),
            r"& C:\Sondera\sondera.exe"
        );
    }

    #[test]
    fn posix_leaves_plain_paths_bare_and_strips_exe() {
        assert_eq!(
            rb("/usr/local/bin/sondera").render(CommandShell::Posix),
            "/usr/local/bin/sondera"
        );
    }

    #[test]
    fn posix_single_quotes_paths_with_spaces() {
        assert_eq!(
            rb("/opt/My Tools/sondera").render(CommandShell::Posix),
            "'/opt/My Tools/sondera'"
        );
    }
}

#[cfg(test)]
mod roundtrip {
    //! The path-splitting bug as a round-trip invariant: for every shell, the executable a
    //! command renders to must survive that shell's own tokenization as exactly
    //! one recoverable path. If it split (the `C:\Program Files` bug), the
    //! oracle recovers `C:\Program` and the property fails.

    use super::*;
    use proptest::prelude::*;

    /// The intended executable path a shell must recover from a rendered token.
    fn expected_exe(path: &str, shell: CommandShell) -> String {
        let simplified = strip_verbatim_prefix(path).to_owned();
        match shell {
            CommandShell::Posix => super::portable_str(Path::new(&simplified)),
            CommandShell::WindowsCmd | CommandShell::PowerShell => super::with_exe(&simplified),
        }
    }

    /// Recover the executable from a POSIX-rendered token: either bare (up to the
    /// first unquoted space) or a single-quoted field with `'\''` escapes.
    fn posix_exe(rendered: &str) -> String {
        if let Some(rest) = rendered.strip_prefix('\'') {
            let mut out = String::new();
            let mut chars = rest.chars().peekable();
            while let Some(ch) = chars.next() {
                if ch == '\'' {
                    // `'\''` is a literal single quote; anything else ends the field.
                    if chars.peek() == Some(&'\\') {
                        chars.next();
                        chars.next(); // the escaped `'`
                        chars.next(); // the reopening `'`
                        out.push('\'');
                        continue;
                    }
                    break;
                }
                out.push(ch);
            }
            out
        } else {
            rendered.split(' ').next().unwrap_or(rendered).to_owned()
        }
    }

    /// Recover the executable from a Windows `cmd` token: either bare (up to the
    /// first space) or a double-quoted field (no in-quote escapes are emitted).
    fn windows_exe(rendered: &str) -> String {
        if let Some(rest) = rendered.strip_prefix('"') {
            rest.split('"').next().unwrap_or(rest).to_owned()
        } else {
            rendered.split(' ').next().unwrap_or(rendered).to_owned()
        }
    }

    /// Recover the executable from a PowerShell token: the leading `& ` call
    /// operator, then a bare or single-quoted (`''`-escaped) field.
    fn powershell_exe(rendered: &str) -> String {
        let rest = rendered.strip_prefix("& ").expect("powershell uses `& `");
        if let Some(inner) = rest.strip_prefix('\'') {
            inner
                .replace("''", "\u{0}")
                .split('\'')
                .next()
                .unwrap_or(inner)
                .replace('\u{0}', "'")
        } else {
            rest.split(' ').next().unwrap_or(rest).to_owned()
        }
    }

    /// Path segments that exercise the bug (spaces) without needing quote-in-path
    /// escaping in the oracle. `\` and `/` build disk and POSIX layouts.
    fn segment() -> impl Strategy<Value = String> {
        prop::string::string_regex("[A-Za-z0-9 ._-]{1,12}").unwrap()
    }

    proptest! {
        #[test]
        fn posix_render_round_trips(prefix in prop::bool::ANY, segs in prop::collection::vec(segment(), 1..4)) {
            let joined = segs.join("/");
            let path = if prefix { format!("/{joined}") } else { joined };
            let binary = ResolvedBinary::from_exe_path(PathBuf::from(&path));
            let rendered = binary.render(CommandShell::Posix);
            prop_assert_eq!(posix_exe(&rendered), expected_exe(&path, CommandShell::Posix));
        }

        #[test]
        fn windows_render_round_trips(segs in prop::collection::vec(segment(), 1..4)) {
            let path = format!(r"C:\{}", segs.join(r"\"));
            let binary = ResolvedBinary::from_exe_path(PathBuf::from(&path));
            let rendered = binary.render(CommandShell::WindowsCmd);
            prop_assert_eq!(windows_exe(&rendered), expected_exe(&path, CommandShell::WindowsCmd));
        }

        #[test]
        fn powershell_render_round_trips(segs in prop::collection::vec(segment(), 1..4)) {
            let path = format!(r"C:\{}", segs.join(r"\"));
            let binary = ResolvedBinary::from_exe_path(PathBuf::from(&path));
            let rendered = binary.render(CommandShell::PowerShell);
            prop_assert_eq!(powershell_exe(&rendered), expected_exe(&path, CommandShell::PowerShell));
        }
    }
}
