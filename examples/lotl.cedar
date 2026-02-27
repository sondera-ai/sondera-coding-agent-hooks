// ═══════════════════════════════════════════════════════
// Sondera – Living off the Land (LotL) Attack Prevention
// ═══════════════════════════════════════════════════════
//
// Guards against attacks that abuse legitimate system tools
// already present on the machine — the hallmark of Living
// off the Land techniques (MITRE ATT&CK TA0001–TA0011).
//
// Unlike signature-based detection (base.cedar) which scans
// content for known patterns, and destructive.cedar which
// blocks irreversible operations, these policies target the
// *misuse of trusted binaries and system mechanisms* that an
// AI agent could leverage for reconnaissance, persistence,
// credential theft, privilege escalation, defense evasion,
// data staging, and execution.
//
// Organized by MITRE ATT&CK tactic:
//
//   §1  Discovery / Reconnaissance  (TA0007)
//   §2  Credential Access           (TA0006)
//   §3  Persistence                 (TA0003)
//   §4  Collection & Data Staging   (TA0009)
//   §5  Privilege Escalation        (TA0004)
//   §6  Defense Evasion             (TA0005)
//   §7  Execution via Interpreters  (TA0002)
//   §8  Compound Guards — LotL + Sensitivity

// ═══════════════════════════════════════════════════════
// §1  Discovery / Reconnaissance (TA0007)
// ═══════════════════════════════════════════════════════
//
// Block system enumeration commands that have no legitimate
// use in a coding agent's workflow. An agent writing code
// never needs to discover network interfaces, running
// processes, listening ports, or other users on the system.

@id("lol-forbid-system-enumeration")
@description("LotL: block system enumeration commands (whoami, id, hostname, uname) — no legitimate coding agent use case.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*whoami*" ||
    context.command like "*id -a*" ||
    context.command like "hostname*" ||
    context.command like "*uname -a*" ||
    context.command like "*hostnamectl*"
};

@id("lol-forbid-network-enumeration")
@description("LotL: block network discovery commands (ifconfig, ip addr, netstat, ss, arp) — agent should not enumerate network topology.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*ifconfig*" ||
    context.command like "*ip addr*" ||
    context.command like "*ip route*" ||
    context.command like "*ip neigh*" ||
    context.command like "*netstat *" ||
    context.command like "*ss -*" ||
    context.command like "*arp -a*" ||
    context.command like "*route -n*"
};

@id("lol-forbid-process-enumeration")
@description("LotL: block process discovery commands (ps aux, top, lsof) — agent should not survey running processes.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*ps aux*" ||
    context.command like "*ps -ef*" ||
    context.command like "*ps -e*" ||
    context.command like "*lsof -i*" ||
    context.command like "*lsof -n*" ||
    context.command like "*lsof +D*"
};

@id("lol-forbid-user-enumeration")
@description("LotL: block user and group enumeration — agent should not discover other accounts on the system.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*cat /etc/passwd*" ||
    context.command like "*cat /etc/group*" ||
    context.command like "*cat /etc/shadow*" ||
    context.command like "*getent passwd*" ||
    context.command like "*getent group*" ||
    context.command like "*dscl . -list*" ||
    context.command like "*last -a*" ||
    context.command like "*w -h*" ||
    context.command like "*users*"
};

@id("lol-forbid-service-enumeration")
@description("LotL: block service discovery commands (systemctl list, launchctl list, service --status-all).")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*systemctl list-*" ||
    context.command like "*launchctl list*" ||
    context.command like "*service --status-all*" ||
    context.command like "*chkconfig --list*"
};

@id("lol-forbid-mount-enumeration")
@description("LotL: block filesystem mount enumeration — agent should not discover attached volumes or network shares.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*mount -l*" ||
    context.command like "*df -h*" ||
    context.command like "*lsblk*" ||
    context.command like "*fdisk -l*" ||
    context.command like "*cat /etc/fstab*" ||
    context.command like "*cat /etc/mtab*" ||
    context.command like "*showmount *"
};

// ─── File reads for system enumeration ───

@id("lol-forbid-read-system-identity")
@description("LotL: block reading system identity files (passwd, group) — agent has no coding use for OS account data.")
forbid (
    principal,
    action == Action::"FileRead",
    resource
) when {
    context.path like "*/etc/passwd" ||
    context.path like "*/etc/group" ||
    context.path like "*/etc/shadow" ||
    context.path like "*/etc/hosts" ||
    context.path like "*/etc/resolv.conf" ||
    context.path like "*/etc/hostname"
};

// ═══════════════════════════════════════════════════════
// §2  Credential Access (TA0006)
// ═══════════════════════════════════════════════════════
//
// Block abuse of system tools to harvest credentials from
// keychains, browser profiles, SSH configs, shell histories,
// and cloud credential stores. These are high-value targets
// that LotL attackers read using standard utilities.

@id("lol-forbid-keychain-access")
@description("LotL: block macOS keychain access via security command — prevents credential extraction from system keychain.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*security find-*" ||
    context.command like "*security dump-keychain*" ||
    context.command like "*security export*" ||
    context.command like "*security show-keychain*"
};

@id("lol-forbid-read-shell-history")
@description("LotL: block reading shell history files — may contain previously typed credentials and tokens.")
forbid (
    principal,
    action == Action::"FileRead",
    resource
) when {
    context.path like "*/.bash_history" ||
    context.path like "*/.zsh_history" ||
    context.path like "*/.history" ||
    context.path like "*/.python_history" ||
    context.path like "*/.node_repl_history" ||
    context.path like "*/.psql_history" ||
    context.path like "*/.mysql_history" ||
    context.path like "*/.rediscli_history"
};

@id("lol-forbid-read-ssh-private-keys")
@description("LotL: block reading SSH private keys and config — prevents lateral movement credential theft.")
forbid (
    principal,
    action == Action::"FileRead",
    resource
) when {
    context.path like "*/.ssh/id_*" ||
    context.path like "*/.ssh/config" ||
    context.path like "*/.ssh/known_hosts" ||
    context.path like "*/.ssh/authorized_keys"
};

@id("lol-forbid-read-cloud-credentials")
@description("LotL: block reading cloud provider credential files — prevents cloud account compromise.")
forbid (
    principal,
    action == Action::"FileRead",
    resource
) when {
    context.path like "*/.aws/credentials" ||
    context.path like "*/.aws/config" ||
    context.path like "*/.azure/accessTokens.json" ||
    context.path like "*/.azure/azureProfile.json" ||
    context.path like "*/.config/gcloud/credentials.db" ||
    context.path like "*/.config/gcloud/application_default_credentials.json" ||
    context.path like "*/.config/gcloud/access_tokens.db" ||
    context.path like "*/.kube/config" ||
    context.path like "*/.docker/config.json"
};

@id("lol-forbid-read-browser-credentials")
@description("LotL: block reading browser credential stores — prevents password and cookie extraction.")
forbid (
    principal,
    action == Action::"FileRead",
    resource
) when {
    context.path like "*/Login Data*" ||
    context.path like "*/Cookies*" ||
    context.path like "*/Web Data*" ||
    context.path like "*/logins.json" ||
    context.path like "*/cookies.sqlite" ||
    context.path like "*/key4.db" ||
    context.path like "*/Keychain.plist"
};

@id("lol-forbid-shell-credential-dump")
@description("LotL: block shell commands that dump credentials from OS stores (credential managers, vaults).")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*credential-osxkeychain*" ||
    context.command like "*secret-tool lookup*" ||
    context.command like "*kwallet-query*" ||
    context.command like "*pass show*" ||
    context.command like "*gpg --export-secret*" ||
    context.command like "*gpg -a --export-secret*"
};

@id("lol-forbid-read-netrc")
@description("LotL: block reading .netrc files — contain plaintext credentials for network services.")
forbid (
    principal,
    action == Action::"FileRead",
    resource
) when {
    context.path like "*/.netrc" ||
    context.path like "*/.curlrc" ||
    context.path like "*/.wgetrc"
};

@id("lol-forbid-env-dump")
@description("LotL: block commands that dump full environment variables — may expose secrets, tokens, and connection strings.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "env" ||
    context.command like "env *" ||
    context.command like "*printenv*" ||
    context.command like "*set | *" ||
    context.command like "*export -p*" ||
    context.command like "*cat /proc/*/environ*"
};

// ═══════════════════════════════════════════════════════
// §3  Persistence (TA0003)
// ═══════════════════════════════════════════════════════
//
// Block modifications to startup mechanisms, scheduled
// tasks, and shell initialization files that would allow
// code to persist across sessions or reboots.

@id("lol-forbid-crontab-modification")
@description("LotL: block crontab manipulation — prevents persistence via scheduled tasks.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*crontab -e*" ||
    context.command like "*crontab -r*" ||
    context.command like "*crontab *" ||
    context.command like "*(crontab*" ||
    context.command like "*at -f*" ||
    context.command like "*atq*" ||
    context.command like "*batch *"
};

@id("lol-forbid-write-cron-dirs")
@description("LotL: block writing to cron directories — prevents persistence via cron.d, cron.daily, etc.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*/etc/cron*" ||
    context.path like "*/var/spool/cron/*" ||
    context.path like "*/var/at/*"
};

@id("lol-forbid-systemd-modification")
@description("LotL: block systemd service creation and modification — prevents persistence via system services.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*systemctl enable *" ||
    context.command like "*systemctl daemon-reload*"
};

@id("lol-forbid-write-systemd-units")
@description("LotL: block writing systemd unit files — prevents persistence via service definitions.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*/systemd/system/*.service" ||
    context.path like "*/systemd/user/*.service" ||
    context.path like "*/etc/init.d/*"
};

@id("lol-forbid-launchd-modification")
@description("LotL: block macOS LaunchAgent/LaunchDaemon creation — prevents persistence via launchd.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*/LaunchAgents/*.plist" ||
    context.path like "*/LaunchDaemons/*.plist"
};

@id("lol-forbid-shell-profile-modification")
@description("LotL: block modification of shell profile and RC files — prevents persistence via shell initialization.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*/.bashrc" ||
    context.path like "*/.bash_profile" ||
    context.path like "*/.bash_login" ||
    context.path like "*/.profile" ||
    context.path like "*/.zshrc" ||
    context.path like "*/.zprofile" ||
    context.path like "*/.zlogin" ||
    context.path like "*/.zshenv" ||
    context.path like "*/etc/profile" ||
    context.path like "*/etc/bash.bashrc" ||
    context.path like "*/etc/zshrc"
};

@id("lol-forbid-authorized-keys-modification")
@description("LotL: block modification of SSH authorized_keys — prevents persistence via SSH backdoor.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*/.ssh/authorized_keys" ||
    context.path like "*/.ssh/authorized_keys2"
};

@id("lol-forbid-git-hooks-modification")
@description("LotL: block modification of git hook scripts — prevents persistence via repository hooks that execute on git operations.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*/.git/hooks/*"
};

// ═══════════════════════════════════════════════════════
// §4  Collection & Data Staging (TA0009)
// ═══════════════════════════════════════════════════════
//
// Block use of system archiving, compression, and encoding
// tools to stage data for exfiltration. LotL attackers use
// tar, zip, and base64 to package sensitive files before
// sending them out via network tools.

@id("lol-forbid-archive-sensitive-dirs")
@description("LotL: block archiving home directories, SSH keys, cloud configs, or git repos — data staging for exfiltration.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    (context.command like "*tar *" ||
     context.command like "*zip *" ||
     context.command like "*7z *" ||
     context.command like "*rar *") &&
    (context.command like "*/.ssh*" ||
     context.command like "*/.aws*" ||
     context.command like "*/.gnupg*" ||
     context.command like "*/.config/gcloud*" ||
     context.command like "*/.kube*" ||
     context.command like "*/etc/shadow*" ||
     context.command like "*/.env*" ||
     context.command like "*/home/*" ||
     context.command like "*/Users/*")
};

@id("lol-forbid-base64-encode-files")
@description("LotL: block base64 encoding of files — common data staging technique to bypass content inspection before exfiltration.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    (context.command like "*base64 *" ||
     context.command like "*openssl enc *" ||
     context.command like "*openssl base64 *") &&
    (context.command like "* < *" ||
     context.command like "* -in *" ||
     context.command like "*| base64*" ||
     context.command like "*-w 0*")
};

@id("lol-forbid-xxd-od-encoding")
@description("LotL: block hex dump tools on sensitive paths — alternate encoding for data staging.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    (context.command like "*xxd *" || context.command like "*od -A x *") &&
    (context.command like "*/.ssh*" ||
     context.command like "*/.aws*" ||
     context.command like "*/.env*" ||
     context.command like "*/etc/shadow*" ||
     context.command like "*secret*" ||
     context.command like "*credential*" ||
     context.command like "*token*")
};

@id("lol-forbid-clipboard-exfiltration")
@description("LotL: block clipboard access commands — prevents data staging via system clipboard.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*pbcopy*" ||
    context.command like "*pbpaste*" ||
    context.command like "*xclip*" ||
    context.command like "*xsel*" ||
    context.command like "*wl-copy*" ||
    context.command like "*wl-paste*"
};

// ═══════════════════════════════════════════════════════
// §5  Privilege Escalation (TA0004)
// ═══════════════════════════════════════════════════════
//
// Block commands that elevate privileges. A coding agent
// should never need root/admin access. Any sudo, su, or
// setuid activity is suspicious in this context.

@id("lol-forbid-sudo")
@description("LotL: block sudo commands — agent should never require elevated privileges.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "sudo *" ||
    context.command like "*sudo *"
};

@id("lol-forbid-su")
@description("LotL: block su commands — agent should not switch to other user accounts.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "su *" ||
    context.command like "su" ||
    context.command like "*| su *" ||
    context.command like "*doas *"
};

@id("lol-forbid-setuid-manipulation")
@description("LotL: block setuid/setgid bit manipulation — prevents privilege escalation via SUID binaries.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*chmod *+s *" ||
    context.command like "*chmod *u+s *" ||
    context.command like "*chmod *g+s *" ||
    context.command like "*chmod 4*" ||
    context.command like "*chmod 2*"
};

@id("lol-forbid-sudoers-modification")
@description("LotL: block modification of sudoers files — prevents granting of elevated privileges.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*/etc/sudoers" ||
    context.path like "*/etc/sudoers.d/*"
};

@id("lol-forbid-suid-discovery")
@description("LotL: block find commands searching for SUID binaries — reconnaissance for privilege escalation.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*find * -perm *4000*" ||
    context.command like "*find * -perm *2000*" ||
    context.command like "*find * -perm */u=s*" ||
    context.command like "*find * -perm */g=s*"
};

// ═══════════════════════════════════════════════════════
// §6  Defense Evasion (TA0005)
// ═══════════════════════════════════════════════════════
//
// Block commands that clear audit trails, disable logging,
// tamper with security tools, or modify system integrity
// mechanisms. An agent covering its tracks is a strong
// indicator of compromise.

@id("lol-forbid-log-clearing")
@description("LotL: block log clearing and truncation commands — prevents evidence destruction.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*truncate -s 0 *log*" ||
    context.command like "*> /var/log/*" ||
    context.command like "*cat /dev/null > *log*" ||
    context.command like "*rm */var/log/*" ||
    context.command like "*journalctl --vacuum*" ||
    context.command like "*log erase *" ||
    context.command like "*history -c*" ||
    context.command like "*history -w*" ||
    context.command like "*unset HISTFILE*" ||
    context.command like "*HISTSIZE=0*" ||
    context.command like "*export HISTFILE=/dev/null*"
};

@id("lol-forbid-security-tool-tampering")
@description("LotL: block disabling of security tools and firewalls — defense evasion via tool suppression.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*systemctl stop *firewall*" ||
    context.command like "*systemctl disable *firewall*" ||
    context.command like "*ufw disable*" ||
    context.command like "*iptables -F*" ||
    context.command like "*iptables -X*" ||
    context.command like "*setenforce 0*" ||
    context.command like "*pfctl -d*" ||
    context.command like "*csrutil disable*" ||
    context.command like "*spctl --master-disable*" ||
    context.command like "*xattr -d com.apple.quarantine*"
};

@id("lol-forbid-audit-tampering")
@description("LotL: block modification of audit configuration — prevents disabling of audit trail.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.path like "*/etc/audit/*" ||
    context.path like "*/etc/rsyslog*" ||
    context.path like "*/etc/syslog*" ||
    context.path like "*/etc/logrotate*"
};

@id("lol-forbid-timestamp-manipulation")
@description("LotL: block timestamp manipulation — timestomping hides malicious file modifications.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*touch -t *" ||
    context.command like "*touch -d *" ||
    context.command like "*touch -r *" ||
    context.command like "*SetFile -d *"
};

// ═══════════════════════════════════════════════════════
// §7  Execution via Interpreters (TA0002)
// ═══════════════════════════════════════════════════════
//
// Block abuse of scripting interpreters to download and
// execute remote payloads. LotL attackers use python, perl,
// ruby, and node as download cradles — fetching code from
// remote servers and executing it in memory without writing
// to disk.

@id("lol-forbid-python-download-exec")
@description("LotL: block Python one-liners that download and execute remote code — classic download cradle technique.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    (context.command like "*python*-c *" ||
     context.command like "*python* -c *") &&
    (context.command like "*urllib*" ||
     context.command like "*requests.get*" ||
     context.command like "*urlopen*" ||
     context.command like "*http.client*" ||
     context.command like "*socket.socket*")
};

@id("lol-forbid-perl-download-exec")
@description("LotL: block Perl one-liners with network capabilities — download cradle via Perl.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*perl -e *" &&
    (context.command like "*LWP::Simple*" ||
     context.command like "*IO::Socket*" ||
     context.command like "*Net::HTTP*" ||
     context.command like "*socket*")
};

@id("lol-forbid-ruby-download-exec")
@description("LotL: block Ruby one-liners with network capabilities — download cradle via Ruby.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*ruby -e *" &&
    (context.command like "*Net::HTTP*" ||
     context.command like "*open-uri*" ||
     context.command like "*TCPSocket*" ||
     context.command like "*net/http*")
};

@id("lol-forbid-node-download-exec")
@description("LotL: block Node.js one-liners with network capabilities — download cradle via Node.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*node -e *" &&
    (context.command like "*http.get*" ||
     context.command like "*https.get*" ||
     context.command like "*fetch(*" ||
     context.command like "*child_process*" ||
     context.command like "*net.Socket*")
};

@id("lol-forbid-pipe-to-interpreter")
@description("LotL: block piping downloaded content to script interpreters — fileless execution via curl/wget pipe to shell/python.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*curl *| bash*" ||
    context.command like "*curl *| sh*" ||
    context.command like "*curl *| zsh*" ||
    context.command like "*curl *| python*" ||
    context.command like "*curl *| perl*" ||
    context.command like "*curl *| ruby*" ||
    context.command like "*curl *| node*" ||
    context.command like "*wget *| bash*" ||
    context.command like "*wget *| sh*" ||
    context.command like "*wget *| python*" ||
    context.command like "*wget *| perl*" ||
    context.command like "*wget * -O - | *" ||
    context.command like "*curl * -o - | *"
};

@id("lol-forbid-eval-from-variable")
@description("LotL: block eval/exec of shell variables — prevents execution of dynamically constructed commands.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*eval $*" ||
    context.command like "*eval \"$*" ||
    context.command like "*bash -c \"$*" ||
    context.command like "*sh -c \"$*" ||
    context.command like "*source /dev/stdin*"
};

// ═══════════════════════════════════════════════════════
// §8  Compound Guards — LotL + Sensitivity Labels
// ═══════════════════════════════════════════════════════
//
// Stricter controls when LotL techniques are detected on
// trajectories that carry sensitive data. These compound
// guards provide defense-in-depth by combining the LotL
// tool patterns with IFC sensitivity labels and YARA
// signature detection.

@id("lol-forbid-archive-on-sensitive-trajectory")
@description("LotL+IFC: block all archiving/compression when trajectory carries confidential or higher data — prevents data staging on sensitive trajectories.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    (resource.label == Label::"Confidential" ||
     resource.label == Label::"HighlyConfidential") &&
    (context.command like "*tar *" ||
     context.command like "*zip *" ||
     context.command like "*gzip *" ||
     context.command like "*bzip2 *" ||
     context.command like "*xz *" ||
     context.command like "*7z *" ||
     context.command like "*rar *")
};

@id("lol-forbid-encoding-on-sensitive-trajectory")
@description("LotL+IFC: block all encoding/decoding commands when trajectory carries sensitive data — prevents data staging via encoding.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    (resource.label == Label::"Confidential" ||
     resource.label == Label::"HighlyConfidential") &&
    (context.command like "*base64 *" ||
     context.command like "*xxd *" ||
     context.command like "*openssl enc *" ||
     context.command like "*uuencode *")
};

@id("lol-forbid-interpreter-on-tainted-trajectory")
@description("LotL+IFC: block scripting interpreter one-liners on trajectories tainted with exfiltration — prevents using interpreters as exfiltration channels.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    resource.taints.contains(Taint::"exfiltration") &&
    (context.command like "*python*-c *" ||
     context.command like "*python* -c *" ||
     context.command like "*perl -e *" ||
     context.command like "*ruby -e *" ||
     context.command like "*node -e *")
};

@id("lol-forbid-discovery-with-signatures")
@description("LotL+Sig: block system enumeration commands when YARA signatures detect additional threat indicators — compound signal of active reconnaissance.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.signature.matches > 0 &&
    (context.command like "*whoami*" ||
     context.command like "id *" ||
     context.command like "* id *" ||
     context.command like "*| id *" ||
     context.command like "*ifconfig*" ||
     context.command like "*netstat *" ||
     context.command like "ps *" ||
     context.command like "* ps *" ||
     context.command like "*| ps *" ||
     context.command like "env" ||
     context.command like "env *" ||
     context.command like "* env" ||
     context.command like "* env *" ||
     context.command like "*| env*" ||
     context.command like "*uname *" ||
     context.command like "*cat /etc/*")
};

@id("lol-forbid-shell-output-credential-on-tainted")
@description("LotL+IFC: block shell output containing credentials on exfiltration-tainted trajectories — prevents credential harvesting during active exfiltration.")
forbid (
    principal,
    action == Action::"ShellCommandOutput",
    resource
) when {
    resource.taints.contains(Taint::"exfiltration") &&
    (context.signature.categories.contains("credential_access") ||
     context.signature.categories.contains("secrets_detection"))
};
