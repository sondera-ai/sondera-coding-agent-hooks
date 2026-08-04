/*
 * Flag Classifier Detection Rules
 *
 * YARA signatures for commands whose risk category is determined by the
 * presence of a specific flag rather than the command name alone:
 *
 *   curl → network_outbound  BUT  curl -d / --json → network_write
 *   git push → git_remote_write  BUT  git push -f → git_history_rewrite
 *   npm install → package_install  BUT  npm install -g → unknown (ask)
 *   python → lang_exec  BUT  python -c "..." → inline lang_exec
 *
 * Note: some curl/wget patterns intentionally overlap with exfil.yar to ensure
 * the action_taxonomy metadata is attached independently of the exfil category.
 */

// ---------------------------------------------------------------------------
// curl — data-sending flags
// Flags: -d, --data, --data-raw, --data-binary, --data-urlencode,
//        -F, --form, --form-string, -T / --upload-file, --json
// ---------------------------------------------------------------------------

rule flags_curl_write_data {
    meta:
        description  = "curl with data-sending flags (-d/--data/-F/--form/-T/--json)"
        action_taxonomy = "network_write"
        severity     = "medium"
        category     = "network_write"
        mitre_attack = "T1071.001"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // -d <data> or -d@<file>
        $d_short    = /\bcurl\b[^\n]*\s-[a-zA-Z]*d(\s|@)/
        // --data, --data-raw, --data-binary, --data-urlencode (space or = separated)
        $data_long  = /\bcurl\b[^\n]*\s--data(-raw|-binary|-urlencode)?(=|\s)/
        // --json <body>
        $data_json  = /\bcurl\b[^\n]*\s--json(=|\s)/
        // -F <form>, --form, --form-string
        $form_short = /\bcurl\b[^\n]*\s-[a-zA-Z]*F\s/
        $form_long  = /\bcurl\b[^\n]*\s--form(-string)?(=|\s)/
        // -T <file> / --upload-file <file>
        $upload_T   = /\bcurl\b[^\n]*\s-[a-zA-Z]*T\s/
        $upload_f   = /\bcurl\b[^\n]*\s--upload-file(=|\s)/

    condition:
        any of them
}

rule flags_curl_write_method {
    meta:
        description  = "curl with explicit write HTTP method (-X POST/PUT/DELETE/PATCH)"
        action_taxonomy = "network_write"
        severity     = "medium"
        category     = "network_write"
        mitre_attack = "T1071.001"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // -X METHOD (space-separated)
        $x_space    = /\bcurl\b[^\n]*\s-X\s+(POST|PUT|DELETE|PATCH)\b/i
        // --request METHOD (space-separated)
        $req_space  = /\bcurl\b[^\n]*\s--request\s+(POST|PUT|DELETE|PATCH)\b/i
        // --request=METHOD (= separated)
        $req_eq     = /\bcurl\b[^\n]*\s--request=(POST|PUT|DELETE|PATCH)\b/i
        // Combined short flags: -XPOST, -sXPOST, -sX POST
        $x_combined = /\bcurl\b[^\n]*\s-[a-zA-Z]*X(POST|PUT|DELETE|PATCH)\b/i

    condition:
        any of them
}

// ---------------------------------------------------------------------------
// wget — POST/write flags
// Flags: --post-data, --post-file, --method=POST/PUT/DELETE/PATCH
// ---------------------------------------------------------------------------

rule flags_wget_write {
    meta:
        description  = "wget with data-send or write-method flags"
        action_taxonomy = "network_write"
        severity     = "medium"
        category     = "network_write"
        mitre_attack = "T1071.001"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        $post_data   = /\bwget\b[^\n]*\s--post-data(=|\s)/
        $post_file   = /\bwget\b[^\n]*\s--post-file(=|\s)/
        $method_eq   = /\bwget\b[^\n]*\s--method=(POST|PUT|DELETE|PATCH)\b/i
        $method_sp   = /\bwget\b[^\n]*\s--method\s+(POST|PUT|DELETE|PATCH)\b/i

    condition:
        any of them
}

// ---------------------------------------------------------------------------
// httpie — write methods and form data
// Commands: http, https, xh, xhs
// Triggers: POST/PUT/DELETE/PATCH method, --form/-f, or key=value data items
// ---------------------------------------------------------------------------

rule flags_httpie_write {
    meta:
        description  = "httpie (http/xh) with write method or form/data flags"
        action_taxonomy = "network_write"
        severity     = "medium"
        category     = "network_write"
        mitre_attack = "T1071.001"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // `\s+` after the command name excludes the `https` URL scheme
        // (`https://`, where `:` follows), not just the httpie name.
        //
        // http/xh with explicit write method as first positional arg
        $write_method = /\b(http|https|xh|xhs)\s+(POST|PUT|DELETE|PATCH)\s/i
        // --form / -f flag (multipart upload)
        $form_flag    = /\b(http|https|xh|xhs)\s+([^\n]*\s)?(--form|-f)\b/
        // Data items: key=value or key:=value (JSON field) after URL
        // Pattern: command <args> word=value or word:=value
        $data_item    = /\b(http|https|xh|xhs)\s+[^\n]*\s\w+:?=[^\s\n]+/

    condition:
        any of them
}

// ---------------------------------------------------------------------------
// git push force flags
// ---------------------------------------------------------------------------

rule flags_git_force_push {
    meta:
        description  = "git push with force, mirror, prune, +refspec or :refspec"
        action_taxonomy = "git_history_rewrite"
        severity     = "high"
        category     = "git_history_rewrite"
        mitre_attack = "T1485"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // -f / --force (space-separated)
        $force_f     = /\bgit\s+push\b[^\n]*\s-f\b/
        $force_long  = /\bgit\s+push\b[^\n]*\s--force\b/
        // --force-with-lease (atomic force)
        $flease      = /\bgit\s+push\b[^\n]*--force-with-lease/
        // --force-if-includes (safe-force variant)
        $fincludes   = /\bgit\s+push\b[^\n]*--force-if-includes/
        // --mirror (replaces remote history entirely)
        $mirror      = /\bgit\s+push\b[^\n]*--mirror\b/
        // --prune (deletes remote refs not in local)
        $prune       = /\bgit\s+push\b[^\n]*--prune\b/
        // --delete <ref> (explicit remote ref deletion)
        $delete      = /\bgit\s+push\b[^\n]*--delete\b/
        // +<refspec> (force-push specific ref)
        $plus_ref    = /\bgit\s+push\b[^\n]*\s\+[a-zA-Z0-9_.\/:-]+/
        // :<refspec> (delete remote ref via empty source)
        $colon_ref   = /\bgit\s+push\b[^\n]*\s:[a-zA-Z0-9_.\/:-]+/
        // Combined short flags containing d (delete) or f (force)
        $combined_f  = /\bgit\s+push\b[^\n]*\s-[a-zA-Z]*[fFdD][a-zA-Z]*/

    condition:
        any of them
}

// ---------------------------------------------------------------------------
// git reset --hard
// ---------------------------------------------------------------------------

rule flags_git_reset_hard {
    meta:
        description  = "git reset --hard discards all staged and unstaged changes"
        action_taxonomy = "git_discard"
        severity     = "high"
        category     = "git_discard"
        mitre_attack = "T1485"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        $reset_hard = /\bgit\s+reset\b[^\n]*--hard\b/

    condition:
        $reset_hard
}

// ---------------------------------------------------------------------------
// git clean -f without dry-run (_classify_git clean → git_history_rewrite
// when force flag present and -n / --dry-run absent)
// ---------------------------------------------------------------------------

rule flags_git_clean_force {
    meta:
        description  = "git clean with -f (force) and no --dry-run"
        action_taxonomy = "git_history_rewrite"
        severity     = "high"
        category     = "git_history_rewrite"
        mitre_attack = "T1485"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // Force flag: -f alone or combined (-fd, -fdx, -fX, etc.)
        $clean_f   = /\bgit\s+clean\b[^\n]*-[a-zA-Z]*f[a-zA-Z]*/
        // Safe variant: -n or --dry-run
        $dry_run   = /\bgit\s+clean\b[^\n]*(-n\b|--dry-run\b)/

    condition:
        $clean_f and not $dry_run
}

// ---------------------------------------------------------------------------
// git branch force-delete (_classify_git branch → git_history_rewrite
// when -D flag or --force + --delete combination)
// ---------------------------------------------------------------------------

rule flags_git_branch_force_delete {
    meta:
        description  = "git branch -D or --force --delete — force removes a branch"
        action_taxonomy = "git_history_rewrite"
        severity     = "high"
        category     = "git_history_rewrite"
        mitre_attack = "T1485"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // -D is the force-delete shorthand (capital D in any short flag cluster)
        $branch_D      = /\bgit\s+branch\b[^\n]*-[a-zA-Z]*D\b/
        // --force present alongside --delete or -d
        $force_flag    = /\bgit\s+branch\b[^\n]*--force\b/
        $delete_flag   = /\bgit\s+branch\b[^\n]*(--delete\b|-[a-zA-Z]*d\b)/

    condition:
        $branch_D or ($force_flag and $delete_flag)
}

// ---------------------------------------------------------------------------
// git tag --force / -f
// ---------------------------------------------------------------------------

rule flags_git_tag_force {
    meta:
        description  = "git tag --force or -f overwrites an existing tag"
        action_taxonomy = "git_history_rewrite"
        severity     = "medium"
        category     = "git_history_rewrite"
        mitre_attack = "T1485"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        $tag_long  = /\bgit\s+tag\b[^\n]*--force\b/
        $tag_short = /\bgit\s+tag\b[^\n]*-[a-zA-Z]*f\b/

    condition:
        any of them
}

// ---------------------------------------------------------------------------
// Global package install flags
// Commands: npm, pnpm, bun, pip, pip3, cargo, gem
// Flags: -g, --global, --system, --target, --root (system-wide installs)
// ---------------------------------------------------------------------------

rule flags_package_global_install {
    meta:
        description  = "Package manager global/system-wide install flags"
        action_taxonomy = "unknown"
        severity     = "medium"
        category     = "package_install"
        mitre_attack = "T1072"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // npm / pnpm / bun global install
        $npm_g       = /\b(npm|pnpm|bun)\b[^\n]*\s(-g|--global|--location=global)\b/
        // pip / pip3 system-wide or custom target install
        $pip_sys     = /\bpip3?\b[^\n]*\s--system\b/
        $pip_target  = /\bpip3?\b[^\n]*\s--target(=|\s+)([\/~]|\.\.)/
        $pip_root    = /\bpip3?\b[^\n]*\s--root(=|\s+)([\/~]|\.\.)/
        // cargo install (always installs to ~/.cargo/bin — system-wide scope)
        $cargo_inst  = /\bcargo\s+install\b/
        // gem install --system
        $gem_sys     = /\bgem\s+install\b[^\n]*--system\b/
        // uv tool install (global tool installation)
        $uv_tool     = /\buv\s+tool\s+install\b/

    condition:
        any of them
}

// ---------------------------------------------------------------------------
// Interpreter inline code flags
// Reclassified as lang_exec; separate from tool_lang_exec (script file)
// ---------------------------------------------------------------------------

rule flags_interpreter_inline {
    meta:
        description  = "Language runtime executing inline code (-c/-e/-r flags)"
        action_taxonomy = "lang_exec"
        severity     = "medium"
        category     = "lang_exec"
        mitre_attack = "T1059"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // python3 -c "code"
        $py_c      = /\bpython3?\s+-c\s+['"]?/
        // node -e "code" / --eval / -p / --print
        $node_e    = /\bnode\s+(-e|--eval|--print|-p)\s+['"]?/
        // ruby -e "code"
        $ruby_e    = /\bruby\s+-e\s+['"]?/
        // perl -e "code" / -E "code"
        $perl_e    = /\bperl\s+(-e|-E)\s+['"]?/
        // php -r "code"
        $php_r     = /\bphp\s+-r\s+['"]?/
        // deno eval / deno run --eval
        $deno_eval = /\bdeno\s+(eval|run\b[^\n]*--eval)\b/
        // bun -e "code"
        $bun_e     = /\bbun\s+-e\s+['"]?/

    condition:
        any of them
}

// ---------------------------------------------------------------------------
// Python -m module mode (_MODULE_FLAGS → lang_exec; distinct from script exec)
// Notable: python -m pytest, python -m http.server, python -m pip install
// ---------------------------------------------------------------------------

rule flags_python_module {
    meta:
        description  = "Python -m module mode execution"
        action_taxonomy = "lang_exec"
        severity     = "low"
        category     = "lang_exec"
        mitre_attack = "T1059.006"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        $py_m = /\bpython3?\s+-m\s+\w+/

    condition:
        $py_m
}

// ---------------------------------------------------------------------------
// find -delete / find -exec rm
// ---------------------------------------------------------------------------

rule flags_find_delete {
    meta:
        description  = "find with -delete action or -exec rm payload"
        action_taxonomy = "filesystem_delete"
        severity     = "high"
        category     = "filesystem_delete"
        mitre_attack = "T1485"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // find ... -delete
        $find_del    = /\bfind\b[^\n]+-delete\b/
        // find ... -exec rm ... \;
        $find_exec_rm = /\bfind\b[^\n]+-exec\s+rm\b/
        // find ... -execdir rm ... \;
        $find_exdir  = /\bfind\b[^\n]+-execdir\s+rm\b/

    condition:
        any of them
}

// ---------------------------------------------------------------------------
// tar extraction with unsafe flags — overwrite, absolute paths, strip-components
// ---------------------------------------------------------------------------

rule flags_tar_overwrite {
    meta:
        description  = "tar with extract + overwrite flags (strips path guards)"
        action_taxonomy = "filesystem_write"
        severity     = "medium"
        category     = "filesystem_write"
        mitre_attack = "T1485"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // tar -xf ... --overwrite
        $tar_over  = /\btar\b[^\n]*--overwrite\b/
        // tar -xf ... --strip-components (path traversal risk)
        $tar_strip = /\btar\b[^\n]*--strip-components\b/
        // tar with -P or --absolute-names (bypasses path stripping)
        $tar_abs   = /\btar\b[^\n]*(-P\b|--absolute-names\b)/

    condition:
        any of them
}
