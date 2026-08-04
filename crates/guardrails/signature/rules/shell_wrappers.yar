/*
 * Shell Wrapper and Execution Indirection Rules
 *
 * YARA signatures for patterns where a benign-looking outer command conceals
 * or delegates actual execution to an inner payload:
 *
 *   bash -c "..."        → shell_wrapper (inner command re-classified)
 *   eval $(...)          → shell_wrapper (command substitution payload)
 *   bash <<< "cmd"       → shell_wrapper (here-string payload)
 *   cmd | bash           → exec_sink_pipe (pipe into interpreter)
 *   base64 -d | python   → obfuscated (decode-to-exec pipeline)
 *   source ./script.sh   → lang_exec (sourced script)
 *   ./script.py          → lang_exec (direct script execution)
 *
 * Interpreter exec sinks:
 *   bash, sh, dash, zsh, eval, python, python3, node, ruby, perl, php,
 *   bun, deno, fish, pwsh, env
 *
 * Decode commands:
 *   base64 -d, base64 --decode, xxd -r, uudecode
 */

// ---------------------------------------------------------------------------
// bash/sh/dash/zsh -c "inner"
// ---------------------------------------------------------------------------

rule shell_wrapper_bash_c {
    meta:
        description  = "Shell -c flag for inline command execution (bash/sh/dash/zsh -c '...')"
        action_taxonomy = "shell_wrapper"
        severity     = "medium"
        category     = "command_execution"
        mitre_attack = "T1059.004"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // Standard: bash -c "command"
        $c_flag    = /\b(bash|sh|dash|zsh)\s+-c\s+['"]?/
        // Combined cluster: bash -lc / bash -cl (login + command)
        $lc_flag   = /\b(bash|sh|dash|zsh)\s+-(lc|cl)\s+['"]?/
        // Additional flags before -c: bash -x -c, bash -ex -c
        $flags_c   = /\b(bash|sh|dash|zsh)\s+-[a-zA-Z]+\s+-c\s+['"]?/

    condition:
        any of them
}

// ---------------------------------------------------------------------------
// bash/sh/dash/zsh <<< "inner"
// ---------------------------------------------------------------------------

rule shell_wrapper_here_string {
    meta:
        description  = "Shell here-string execution pattern (bash <<< 'command')"
        action_taxonomy = "shell_wrapper"
        severity     = "medium"
        category     = "command_execution"
        mitre_attack = "T1059.004"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // Shell followed by <<<
        $here_shell = /\b(bash|sh|dash|zsh)\b[^\n]*<<<\s*['"]?/
        // <<< used as standalone redirect (piping without pipe)
        $here_bare  = /<<<\s*['"][^'"]{5,}/

    condition:
        any of them
}

// ---------------------------------------------------------------------------
// eval "string" / eval $(...) / eval `...`
// ---------------------------------------------------------------------------

rule shell_wrapper_eval {
    meta:
        description  = "eval-based command execution (eval '...', eval $(), eval `...`)"
        action_taxonomy = "shell_wrapper"
        severity     = "high"
        category     = "command_execution"
        mitre_attack = "T1059.004"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // eval "string" / eval 'string' (quoted payload)
        $eval_str   = /\beval\s+["'][^"']{3,}/
        // eval $(...) — command substitution as payload
        $eval_sub   = /\beval\s+\$\(/
        // eval `...` — backtick substitution as payload
        $eval_back  = /\beval\s+`/
        // eval $VAR — variable as payload
        $eval_var   = /\beval\s+\$[A-Za-z_][A-Za-z0-9_]*/
        // Python exec("string") / exec(compile(...))
        $py_exec    = /\bexec\s*\(\s*["'][^"']{5,}/
        // JavaScript eval("string")
        $js_eval    = /\beval\s*\(\s*["'][^"']{5,}/

    condition:
        any of them
}

// ---------------------------------------------------------------------------
// source / .
// _SHELL_WRAPPERS does not include source; it falls through to lang_exec.
// ---------------------------------------------------------------------------

rule shell_source_exec {
    meta:
        description  = "Shell source / dot-operator script execution (source ./env.sh)"
        action_taxonomy = "lang_exec"
        severity     = "medium"
        category     = "command_execution"
        mitre_attack = "T1059.004"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // source <file> with recognised shell extensions
        $source_sh = /\bsource\s+[^\s\n]+\.(sh|bash|zsh|fish|env)\b/
        // source with path prefix but no extension (env files, rc files)
        $source_rel = /\bsource\s+\.\/[^\s\n]+\b/
        // dot operator: . ./script.sh — matched as whitespace-dot-space or just dot-space
        // at command positions (after &&, ;, or start of a pipeline segment).
        $dot_sh    = /\s\.\s+[^\s\n]+\.(sh|bash|zsh|fish|env)\b/
        $dot_rel   = /\s\.\s+\.\/[^\s\n]+\b/

    condition:
        any of them
}

// ---------------------------------------------------------------------------
// Pipe into exec sinks
// Fired when any command's stdout feeds into a recognised interpreter.
// EXEC_SINKS: bash sh dash zsh eval python python3 node ruby perl php
//             bun deno fish pwsh env
// ---------------------------------------------------------------------------

rule shell_pipe_to_interpreter {
    meta:
        description  = "Command piped into a language-runtime exec sink (cmd | bash, cmd | python)"
        action_taxonomy = "exec_sink_pipe"
        severity     = "high"
        category     = "command_execution"
        mitre_attack = "T1059"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // Pipe to POSIX shells
        $p_bash    = /\|\s*(bash|sh|dash|zsh|fish)\b/
        // Pipe to Python (with optional version suffix)
        $p_python  = /\|\s*python3?\b/
        // Pipe to Node.js
        $p_node    = /\|\s*node\b/
        // Pipe to Ruby
        $p_ruby    = /\|\s*ruby\b/
        // Pipe to Perl
        $p_perl    = /\|\s*perl\b/
        // Pipe to PHP
        $p_php     = /\|\s*php\b/
        // Pipe to modern runtimes
        $p_bun     = /\|\s*(bun|deno|pwsh)\b/
        // Pipe to env (env <interp> launches interpreter via PATH)
        $p_env     = /\|\s*env\s+\w/

    condition:
        any of them
}

// ---------------------------------------------------------------------------
// Decode-to-exec pipelines — action_taxonomy: obfuscated
// Decode commands: base64 -d, base64 --decode, xxd -r, uudecode
// ---------------------------------------------------------------------------

rule shell_decode_to_exec {
    meta:
        description  = "Decode-to-execute pipeline: base64/xxd/uudecode output piped to an interpreter"
        action_taxonomy = "obfuscated"
        severity     = "critical"
        category     = "obfuscation"
        mitre_attack = "T1027.010"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // base64 -d / --decode piped to any interpreter (exec sink)
        $b64_pipe   = /base64\s+(--decode|-d)[^\n]*\|\s*(bash|sh|dash|zsh|python3?|node|ruby|perl|php|bun|deno|fish|pwsh)/

        // xxd -r (hex decode) piped to interpreter
        $xxd_pipe   = /xxd\s+-r[^\n]*\|\s*(bash|sh|dash|zsh|python3?|node|ruby|perl|php)/

        // uudecode piped to interpreter (bare invocation — no flag required)
        $uu_pipe    = /uudecode[^\n]*\|\s*(bash|sh|dash|zsh|python3?|node|ruby|perl|php)/

        // openssl enc -d (binary decode) piped to interpreter
        $openssl_d  = /openssl\s+enc\s+-d[^\n]*\|\s*(bash|sh|dash|zsh|python3?|node)/

        // Python exec(base64.b64decode(...)) / exec(b64decode(...))
        $py_b64exec = /exec\s*\(\s*(base64\.b64decode|b64decode)\s*\(/

        // Python exec(compile(...)) — dynamic compilation
        $py_compile = /exec\s*\(\s*compile\s*\(/

        // Node.js eval(Buffer.from(...,'base64').toString()) / eval(atob(...))
        $js_b64eval = /eval\s*\(\s*(Buffer\.from|atob)\s*\(/

        // PHP eval(base64_decode(...))
        $php_b64    = /eval\s*\(\s*base64_decode\s*\(/

    condition:
        any of them
}

// ---------------------------------------------------------------------------
// Direct script execution by path (./ or /abs/path prefix)
// Extensions: .py .js .rb .sh .pl .ts .php .tsx
// ---------------------------------------------------------------------------

rule shell_script_direct_exec {
    meta:
        description  = "Direct script file execution by relative or absolute path (./script.py, /opt/script.sh)"
        action_taxonomy = "lang_exec"
        severity     = "medium"
        category     = "lang_exec"
        mitre_attack = "T1059"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // ./ prefix with recognised script extension
        $rel_py   = /\.(\/|\\)[^\s\n]*\.py\b/
        $rel_js   = /\.(\/|\\)[^\s\n]*\.(m?[jt]sx?|cjs)\b/
        $rel_rb   = /\.(\/|\\)[^\s\n]*\.rb\b/
        $rel_sh   = /\.(\/|\\)[^\s\n]*\.(sh|bash)\b/
        $rel_pl   = /\.(\/|\\)[^\s\n]*\.pl\b/
        $rel_php  = /\.(\/|\\)[^\s\n]*\.php\b/

    condition:
        any of them
}

// ---------------------------------------------------------------------------
// env as exec-sink launcher
// env python3 <args>, env node <args>
// (Low severity: also appears in #!/usr/bin/env shebangs)
// ---------------------------------------------------------------------------

rule shell_env_launcher {
    meta:
        description  = "env used as interpreter launcher (env python3, env node)"
        action_taxonomy = "lang_exec"
        severity     = "low"
        category     = "command_execution"
        mitre_attack = "T1059"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // env <interpreter> on a command line (not in a shebang)
        $env_interp  = /\benv\s+(python3?|node|ruby|perl|php|bash|sh|deno|bun)\b/
        // Shebang line: #!/usr/bin/env python3
        $shebang_env = /#!\/usr\/bin\/env\s+(python3?|node|ruby|perl|php|bash|sh)/

    condition:
        any of them
}

// ---------------------------------------------------------------------------
// Script interpreter via PATH with version suffix (python3.12, node22)
// ---------------------------------------------------------------------------

rule shell_versioned_interpreter {
    meta:
        description  = "Versioned interpreter invocation (python3.12, node22, ruby3.2)"
        action_taxonomy = "lang_exec"
        severity     = "low"
        category     = "lang_exec"
        mitre_attack = "T1059"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // python3.x / python3.x.y
        $py_ver   = /\bpython3\.[0-9]+(\.[0-9]+)?\b/
        // node with version suffix
        $node_ver = /\bnode[0-9]+(\.[0-9]+)?\b/
        // ruby with version
        $ruby_ver = /\bruby[0-9]+(\.[0-9]+)?\b/
        // bash with version
        $bash_ver = /\bbash[0-9]+(\.[0-9]+)?\b/

    condition:
        any of them
}
