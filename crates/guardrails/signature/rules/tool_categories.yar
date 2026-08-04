/*
 * Tool Category Detection Rules
 *
 * YARA signatures covering operation categories that carry elevated risk
 * for AI agent trajectories:
 *   filesystem_delete, git_history_rewrite, git_discard, network_write,
 *   lang_exec, package_uninstall, process_signal, container_destructive,
 *   db_write, sensitive_path.
 *
 * These rules are orthogonal to injection.yar / exfil.yar / secrets.yar.
 * Each rule carries an action_taxonomy metadata field so downstream policy
 * can reason about the class of operation, not just the raw match.
 */

// ---------------------------------------------------------------------------
// filesystem_delete — rm, shred, truncate, find -delete, Python destructors
// ---------------------------------------------------------------------------

rule tool_filesystem_destructive {
    meta:
        description  = "Detects destructive filesystem operations: recursive delete, shred, truncate, find -delete"
        action_taxonomy = "filesystem_delete"
        severity     = "high"
        category     = "filesystem_delete"
        mitre_attack = "T1485"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // rm with recursive + force flag combination
        $rm_rf    = /\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\b/
        $rm_fr    = /\brm\s+-[a-zA-Z]*f[a-zA-Z]*r\b/
        // rm -r alone (recursive without force)
        $rm_r     = /\brm\s+-[a-zA-Z]*r\b/

        // shred with -u (unlink) or -z (zero)
        $shred    = /\bshred\s+-[a-zA-Z]*[uz]\b/

        // truncate to size zero
        $truncate = /\btruncate\s+-s\s+0\b/

        // find with -delete action
        $find_del = /\bfind\b[^\n]+-delete\b/

        // Python: shutil.rmtree(), os.remove(), os.unlink()
        $rmtree   = /\bshutil\.rmtree\s*\(/
        $os_rm    = /\bos\.(remove|unlink)\s*\(/

        // Windows: rmdir /s, del /f
        $win_rmd  = /\brmdir\s+\/[Ss]\b/
        $win_del  = /\bdel\s+\/[Ff]\b/

    condition:
        any of them
}

// ---------------------------------------------------------------------------
// git_history_rewrite — force-push, amend, rebase, filter-branch, clean -f
// ---------------------------------------------------------------------------

rule tool_git_history_rewrite {
    meta:
        description  = "Detects git operations that rewrite history or permanently discard data"
        action_taxonomy = "git_history_rewrite"
        severity     = "high"
        category     = "git_history_rewrite"
        mitre_attack = "T1485"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // git push with force variants
        $push_f      = /\bgit\s+push\b[^\n]*\s(-f\b|--force\b)/
        $push_flease = /\bgit\s+push\b[^\n]*--force-with-lease/
        $push_mirror = /\bgit\s+push\b[^\n]*--mirror\b/
        $push_prune  = /\bgit\s+push\b[^\n]*--prune\b/
        // force-push a specific ref: git push origin +main
        $push_plus   = /\bgit\s+push\b[^\n]*\s\+[a-zA-Z0-9_.\/:-]+/
        // delete a remote ref: git push origin :branch
        $push_colon  = /\bgit\s+push\b[^\n]*\s:[a-zA-Z0-9_.\/:-]+/
        // git push --delete <ref>
        $push_del    = /\bgit\s+push\b[^\n]*--delete\b/

        // git reset --hard
        $reset_hard  = /\bgit\s+reset\b[^\n]*--hard\b/

        // git clean with force (without dry-run handled in flag_classifiers.yar)
        $clean_f     = /\bgit\s+clean\s+-[a-zA-Z]*f[a-zA-Z]*/

        // git commit --amend
        $amend       = /\bgit\s+commit\b[^\n]*--amend\b/

        // git filter-branch / git filter-repo
        $filter_b    = /\bgit\s+filter-branch\b/
        $filter_r    = /\bgit\s+filter-repo\b/

        // git stash drop / clear
        $stash_drop  = /\bgit\s+stash\s+(drop|clear)\b/

        // git branch force-delete: -D flag
        $branch_D    = /\bgit\s+branch\b[^\n]*-[a-zA-Z]*D\b/

        // git tag --force / -f
        $tag_force   = /\bgit\s+tag\b[^\n]*(--force\b|-f\b)/

        // gh repo delete / archive
        $gh_del_repo = /\bgh\s+repo\s+(delete|archive)\b/

    condition:
        any of them
}

// ---------------------------------------------------------------------------
// git_discard — explicit discard-changes indicators
// ---------------------------------------------------------------------------

rule tool_git_discard {
    meta:
        description  = "Detects git operations that discard uncommitted working-tree changes"
        action_taxonomy = "git_discard"
        severity     = "medium"
        category     = "git_discard"
        mitre_attack = "T1485"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // git checkout with discard indicators
        // Note: \b cannot follow non-word chars (. and --) so patterns end without \b
        $checkout_dot  = /\bgit\s+checkout\s+\./
        $checkout_dash = /\bgit\s+checkout\s+--/

        // git switch --discard-changes or --force
        $switch_disc   = /\bgit\s+switch\b[^\n]*(--discard-changes|--force)\b/

        // git restore (restores working-tree file — destructive without --staged)
        $restore       = /\bgit\s+restore\b/

        // git rm (removes tracked files)
        $git_rm        = /\bgit\s+rm\b/

    condition:
        any of them
}

// ---------------------------------------------------------------------------
// network_write — publish operations not covered by exfil.yar
// ---------------------------------------------------------------------------

rule tool_network_write {
    meta:
        description  = "Detects intentional publish / registry-write network operations"
        action_taxonomy = "network_write"
        severity     = "medium"
        category     = "network_write"
        mitre_attack = "T1071.001"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // Package registry publish
        $npm_pub    = /\bnpm\s+(publish|unpublish|deprecate)\b/
        $yarn_pub   = /\byarn\s+(npm\s+)?publish\b/
        $pnpm_pub   = /\bpnpm\s+publish\b/
        $cargo_pub  = /\bcargo\s+publish\b/
        $twine      = /\btwine\s+upload\b/
        $gem_push   = /\bgem\s+push\b/

        // Python requests write methods (complement exfil.yar which has .post)
        $req_delete = /\brequests\.(delete|patch|put)\s*\(/
        $req_put    = /\bhttpx\.(post|put|patch|delete)\s*\(/

        // gh api with explicit write method
        $gh_api_w   = /\bgh\s+api\b[^\n]*(--method\s+(POST|PUT|DELETE|PATCH)|-(X|method)\s+(POST|PUT|DELETE|PATCH))/i

    condition:
        any of them
}

// ---------------------------------------------------------------------------
// lang_exec — interpreter running a script file (not inline -c/-e code)
// ---------------------------------------------------------------------------

rule tool_lang_exec {
    meta:
        description  = "Detects language runtimes executing a script file (python script.py, node app.js, etc.)"
        action_taxonomy = "lang_exec"
        severity     = "medium"
        category     = "lang_exec"
        mitre_attack = "T1059"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // Python: interpreter followed by a .py file (first arg starts with non-dash)
        // Pattern: python3? <non-flag-char>...<something>.py
        $py_script   = /\bpython3?\s+[^\s\-\n][^\n]*\.py\b/

        // Node: interpreter followed by a .js/.mjs/.cjs file
        $node_script = /\bnode\s+[^\s\-\n][^\n]*\.(m?[jt]sx?|cjs)\b/

        // Ruby script file
        $ruby_script = /\bruby\s+[^\s\-\n][^\n]*\.rb\b/

        // Perl script file
        $perl_script = /\bperl\s+[^\s\-\n][^\n]*\.pl\b/

        // PHP script file
        $php_script  = /\bphp\s+[^\s\-\n][^\n]*\.php\b/

        // Rscript (always runs a file; no inline equivalent)
        $rscript     = /\bRscript\s+[^\s\-\n][^\n]*\.R\b/

        // TypeScript via tsx / ts-node
        $ts_script   = /\b(tsx|ts-node)\s+[^\s\-\n][^\n]*\.tsx?\b/

        // Bun running a script
        $bun_script  = /\bbun\s+run\s+[^\s\-\n][^\n]*\.(ts|js|tsx?)\b/

    condition:
        any of them
}

// ---------------------------------------------------------------------------
// package_uninstall — pip/npm/gem/brew/apt remove
// ---------------------------------------------------------------------------

rule tool_package_uninstall {
    meta:
        description  = "Detects package removal commands (pip uninstall, npm uninstall, apt remove, brew uninstall)"
        action_taxonomy = "package_uninstall"
        severity     = "medium"
        category     = "package_uninstall"
        mitre_attack = "T1485"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        $pip_unin   = /\bpip3?\s+uninstall\b/
        $uv_unin    = /\buv\s+(pip\s+uninstall|remove|tool\s+uninstall|python\s+uninstall)\b/
        $npm_unin   = /\b(npm|pnpm)\s+(uninstall|remove|rm|unlink)\b/
        $yarn_rem   = /\byarn\s+remove\b/
        $bun_rem    = /\bbun\s+remove\b/
        $gem_unin   = /\bgem\s+uninstall\b/
        $cargo_rem  = /\bcargo\s+remove\b/
        $apt_rem    = /\bapt(-get)?\s+(remove|purge)\b/
        $brew_unin  = /\bbrew\s+(uninstall|remove)\b/
        $dnf_rem    = /\bdnf\s+remove\b/
        $yum_rem    = /\byum\s+remove\b/
        $apk_del    = /\bapk\s+del\b/

    condition:
        any of them
}

// ---------------------------------------------------------------------------
// process_signal — kill -9, pkill, killall
// ---------------------------------------------------------------------------

rule tool_process_signal {
    meta:
        description  = "Detects process termination signals (SIGKILL, pkill, killall)"
        action_taxonomy = "process_signal"
        severity     = "medium"
        category     = "process_signal"
        mitre_attack = "T1489"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // kill with explicit numeric or named SIGKILL / SIGTERM
        $kill_9    = /\bkill\s+(-9|-KILL|-SIGKILL)\b/
        $kill_15   = /\bkill\s+(-15|-TERM|-SIGTERM)\b/

        // pkill / killall send signal to process name
        $pkill     = /\bpkill\b/
        $killall   = /\bkillall\b/

        // Windows: taskkill /F
        $taskkill  = /\btaskkill\s+\/[Ff]\b/

    condition:
        any of them
}

// ---------------------------------------------------------------------------
// container_destructive — docker rm/rmi/prune, kubectl delete, podman rm
// ---------------------------------------------------------------------------

rule tool_container_destructive {
    meta:
        description  = "Detects destructive container and orchestration operations"
        action_taxonomy = "container_destructive"
        severity     = "high"
        category     = "container_destructive"
        mitre_attack = "T1485"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // docker rm / rmi
        $docker_rm    = /\bdocker\s+rm\b/
        $docker_rmi   = /\bdocker\s+rmi\b/

        // docker prune — all subsystems
        $docker_prune = /\bdocker\s+(system|container|image|volume|network|builder|buildx)\s+prune\b/

        // docker volume rm (explicit volume removal)
        $docker_vol   = /\bdocker\s+volume\s+rm\b/

        // docker compose down / rm
        $compose_down = /\bdocker[\s-]compose\s+down\b/
        $compose_rm   = /\bdocker[\s-]compose\s+rm\b/

        // docker buildx rm (removes builders)
        $buildx_rm    = /\bdocker\s+buildx\s+rm\b/

        // kubectl delete — removes cluster resources
        $k8s_del      = /\bkubectl\s+delete\b/

        // podman destructive
        $podman_rm    = /\bpodman\s+(rm|rmi)\b/
        $podman_prune = /\bpodman\s+(system|volume|image|container)\s+prune\b/

    condition:
        any of them
}

// ---------------------------------------------------------------------------
// db_write — SQL modification via CLI clients (psql, mysql, sqlite3)
// ---------------------------------------------------------------------------

rule tool_db_write {
    meta:
        description  = "Detects database write and schema-change operations via CLI clients"
        action_taxonomy = "db_write"
        severity     = "medium"
        category     = "db_write"
        mitre_attack = "T1485"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // psql with an inline write command
        $psql_c  = /\bpsql\b[^\n]*(-c|--command)\s+['"]?\s*(INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE)\b/i

        // psql executing a file (content unknown, flag for review)
        $psql_f  = /\bpsql\b[^\n]*(-f|--file)\b/

        // mysql with an inline write command
        $mysql_e = /\bmysql\b[^\n]*(-e|--execute)\s+['"]?\s*(INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE)\b/i

        // sqlite3 with a write statement as argument
        $sqlite  = /\bsqlite3\b[^\n]*(INSERT|UPDATE|DELETE|DROP|TRUNCATE|ALTER|CREATE)\b/i

        // Raw SQL write keywords — flagged when two or more distinct types appear
        // together (reduces false positives from SQL in source comments)
        $sql_ins  = /\bINSERT\s+INTO\b/i
        $sql_upd  = /\bUPDATE\b[^\n]+\bSET\b/i
        $sql_del  = /\bDELETE\s+FROM\b/i
        $sql_drop = /\bDROP\s+(TABLE|DATABASE|SCHEMA|INDEX)\b/i
        $sql_trnc = /\bTRUNCATE\s+TABLE\b/i
        $sql_alt  = /\bALTER\s+(TABLE|COLUMN|INDEX)\b/i

    condition:
        any of ($psql_c, $psql_f, $mysql_e, $sqlite) or
        2 of ($sql_ins, $sql_upd, $sql_del, $sql_drop, $sql_trnc, $sql_alt)
}

// ---------------------------------------------------------------------------
// sensitive_path — credential directories and sensitive config files
// ---------------------------------------------------------------------------

rule tool_sensitive_path_access {
    meta:
        description  = "Detects access to sensitive credential directories and configuration files"
        action_taxonomy = "sensitive_path"
        severity     = "high"
        category     = "credential_access"
        mitre_attack = "T1552.001"
        author       = "Sondera Security"
        date         = "2025-03-26"

    strings:
        // SSH, GPG, and auth credential files (path patterns match both
        // separators + nocase: Windows fleets report \-separated,
        // case-insensitive paths)
        $ssh_dir    = /[\/\\]\.ssh[\/\\]/ nocase
        $gnupg_dir  = /[\/\\]\.gnupg[\/\\]/ nocase
        $git_creds  = ".git-credentials"
        $netrc      = /[\/\\]\.netrc/ nocase

        // Cloud provider credential directories
        $aws_dir    = /[\/\\]\.aws[\/\\]/ nocase
        $azure_dir  = /[\/\\]\.azure[\/\\]/ nocase
        $gcloud_dir = /[\/\\]\.config[\/\\]gcloud/ nocase
        // Windows gcloud config dir lives under %APPDATA%, no .config prefix
        $gcloud_win = /[\/\\]AppData[\/\\]Roaming[\/\\]gcloud/ nocase
        $gh_cfg     = /[\/\\]\.config[\/\\]gh/ nocase
        $docker_cfg = /[\/\\]\.docker[\/\\]config\.json/ nocase
        $tf_creds   = "credentials.tfrc.json"
        $claude_set = /[\/\\]\.claude[\/\\]settings/ nocase

        // Sensitive environment and registry files
        $env_local  = ".env.local"
        $env_prod   = ".env.production"
        $npmrc      = ".npmrc"
        $pypirc     = ".pypirc"

    condition:
        any of them
}
