/*
 * Command Injection Detection Rules
 *
 * Detects command injection attempts in AI agent interactions including:
 * - Shell command chaining
 * - Path traversal
 * - Command substitution
 * - Privilege escalation
 * - Environment variable manipulation
 */

rule command_injection_shell_chaining {
    meta:
        description = "Detects shell command chaining operators (&&, ||, ;, |)"
        severity = "critical"
        category = "command_injection"
        mitre_attack = "T1059.004"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        $cmd1 = /\&\&\s*[a-zA-Z]/ // && followed by command
        $cmd2 = /\|\|\s*[a-zA-Z]/ // || followed by command
        $cmd3 = /;\s*[a-zA-Z]+/ // ; followed by command
        $cmd4 = /\|\s*[a-zA-Z]+/ // | followed by command
        $cmd5 = /`[^`]*\s[^`]*`/ // Backtick command substitution (requires space to avoid markdown false positives)
        $cmd6 = /\$\([^\)]+\)/ // $() command substitution

    condition:
        any of them
}

rule command_injection_path_traversal {
    meta:
        description = "Detects path traversal patterns in commands"
        severity = "high"
        category = "command_injection"
        mitre_attack = "T1083"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        $path1 = "../" nocase
        $path2 = "..%2f" nocase // URL encoded
        $path3 = "..%5c" nocase // Backslash encoded
        $path4 = /\.\.[\/]/ // Any traversal

    condition:
        2 of them // Require multiple occurrences
}

rule command_injection_dangerous_commands {
    meta:
        description = "Detects execution of dangerous system commands"
        severity = "critical"
        category = "command_injection"
        mitre_attack = "T1059"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // Network operations
        $curl_pipe = /curl[^|]*\|\s*(sh|bash)/ nocase
        $wget_exec = /wget[^&]*&&\s*(sh|bash)/ nocase

    condition:
        any of them
}

rule command_injection_sensitive_files {
    meta:
        description = "Detects access to sensitive system files"
        severity = "critical"
        category = "command_injection"
        mitre_attack = "T1552.001"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // Password files
        $passwd = "/etc/passwd" nocase
        $shadow = "/etc/shadow" nocase

        // SSH keys
        $ssh_priv = "/.ssh/id_rsa" nocase
        $ssh_keys = "/.ssh/authorized_keys" nocase

        // Cloud credentials
        $aws = "/.aws/credentials" nocase
        $gcp = "/.config/gcloud" nocase
        $azure = "/.azure/credentials" nocase

        // Environment variables
        $env = "/proc/self/environ" nocase

        // Database configs
        $mysql = "/etc/mysql" nocase
        $postgres = "/etc/postgresql" nocase

    condition:
        any of them
}

rule command_injection_environment_manipulation {
    meta:
        description = "Detects manipulation of environment variables"
        severity = "high"
        category = "command_injection"
        mitre_attack = "T1574.007"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        $ld_preload = "LD_PRELOAD" fullword ascii
        $ld_library = "LD_LIBRARY_PATH" fullword ascii
        $path_mod = /PATH\s*=.*:/ fullword ascii
        $dyld = "DYLD_INSERT_LIBRARIES" fullword ascii
        $prompt_cmd = "PROMPT_COMMAND" fullword ascii
        $histfile = "HISTFILE" fullword ascii

    condition:
        any of them
}

rule command_injection_sql_injection {
    meta:
        description = "Detects SQL injection in command arguments"
        severity = "critical"
        category = "command_injection"
        mitre_attack = "T1190"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // SQL injection patterns
        $sql1 = "'; DROP TABLE" nocase
        $sql2 = "'; DROP DATABASE" nocase
        $sql3 = "'; TRUNCATE TABLE" nocase
        $sql4 = "' OR '1'='1" nocase
        $sql5 = "' OR 1=1--" nocase
        $sql6 = "UNION SELECT" nocase
        $sql7 = "'; EXEC(" nocase
        $sql8 = /'\s*OR\s+[a-zA-Z0-9_]+\s*=\s*[a-zA-Z0-9_]+/ nocase

    condition:
        any of them
}

rule command_injection_process_substitution {
    meta:
        description = "Detects process substitution for command injection"
        severity = "high"
        category = "command_injection"
        mitre_attack = "T1059"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        $proc1 = /<\([^\)]+\)/ // <() process substitution
        $proc2 = />\([^\)]+\)/ // >() process substitution
        $heredoc = /<<[A-Z_]+/ // Here document

    condition:
        any of them
}

rule command_injection_obfuscated_separators {
    meta:
        description = "Detects obfuscated command separators"
        severity = "high"
        category = "command_injection"
        mitre_attack = "T1027.010"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        // Tab characters as separators
        $tab = /\t[a-z]{2,}/
        $tab2 = "%09%09"

        $url_encoded_exec = "%26%26" // &&
        $url_encoded_exec2 = "%7C" // |
        $url_encoded_exec3 = "%3B" // ;

    condition:
        any of them
}

rule command_injection_reverse_shell {
    meta:
        description = "Detects reverse shell patterns"
        severity = "critical"
        category = "command_injection"
        mitre_attack = "T1059.004"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        $bash_tcp = "/dev/tcp/" nocase
        $bash_udp = "/dev/udp/" nocase
        $nc_listen = /nc.*-[a-z]*l.*-[a-z]*p/ nocase
        $nc_exec = /nc.*-[a-z]*e/ nocase

    condition:
        any of them
}

rule command_injection_programatic_shell {
    meta:
        description = "Detects reverse shell patterns in prog languages"
        severity = "critical"
        category = "command_injection"
        mitre_attack = "T1059.004"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        $perl_socket = "use Socket" nocase
        $python_socket = "socket.socket" nocase
        $python_pty = "pty.spawn" nocase
        $python_dup2 = "os.dup2" nocase
        $python_clear_history = "os.putenv(\"HISTFILE\"" fullword ascii
        $ruby_socket = "TCPSocket.new" nocase

    condition:
        any of them
}

rule command_injection_cron_manipulation {
    meta:
        description = "Detects cron job manipulation attempts"
        severity = "critical"
        category = "command_injection"
        mitre_attack = "T1053.003"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        $crontab = /crontab\s+-[a-z]/ nocase
        $cron_dir = "/etc/cron" nocase
        $cron_d = "/etc/cron.d" nocase
        $var_spool = "/var/spool/cron" nocase
        $cron_schedule = /\*\s+\*\s+\*\s+\*\s+\*/ // Cron schedule pattern

    condition:
        any of them
}

rule command_injection_php {
    meta:
        description = "PHP calls to dangerous shell exec functions with variable arguments"
        severity = "high"
        category = "command_injection"
        mitre_attack = "T1053.003"
        author = "Sondera Security"
        date = "2025-11-26"

    strings:
        $cmd1 = /(escapeshellcmd|exec|system|passthru|popen)\s*\([^\(,]*\$/ nocase

        // detect common web-request variables near invocations:
        $v1 = /(\$_GET|\$_POST|\$_REQUEST)\s*\[.*\]/ nocase

    condition:
        $cmd1 and $v1
}
