// ─────────────────────────────────────────────────────
// Insider Threat Detection Policy
// ─────────────────────────────────────────────────────
//
// Detects and blocks AI agent actions that indicate insider threat
// behaviors: credential harvesting, data exfiltration, and suspicious
// file access patterns combined with network activity.
//
// Threat Model:
// 1. Credential Access: Agent reads files matching credential patterns
//    (.env, .aws/credentials, .ssh/*, cloud config files)
// 2. Data Exfiltration: Agent sends collected data to external services
//    (paste sites, external domains, DNS tunneling)
// 3. Taint Propagation: Once an agent accesses credentials, the
//    trajectory is marked with "credential_access" taint. Further
//    exfiltration attempts are blocked.
// 4. Privilege Escalation: Suspicious commands (reverse shells, cron
//    manipulation) on tainted trajectories indicate coordinated attack
//
// Enforcement Strategy:
// - Forbid all credential file reads (detected via YARA)
// - Forbid all highly confidential file reads
// - Forbid all shell commands that probe for credentials
// - Forbid exfiltration patterns (paste sites, external network calls)
// - Forbid web/shell activity on tainted trajectories
// - Forbid cross-sensitivity file writes (confidential → public)
//
// This multi-layered approach prevents both individual suspicious
// actions and attack chains that combine reconnaissance, access,
// and exfiltration phases.

@id("forbid-credential-access-read")
forbid (
    principal,
    action == Action::"FileRead",
    resource
)
when {
    context.signature.categories.contains("credential_access") ||
    context.signature.categories.contains("secrets_detection")
};

@id("forbid-file-read-highly-confidential")
forbid (
    principal,
    action == Action::"FileRead",
    resource
)
when {
    resource.label == Label::"HighlyConfidential"
};

@id("forbid-shell-credential-access")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
)
when {
    context.signature.categories.contains("credential_access")
};

@id("forbid-shell-output-secrets")
forbid (
    principal,
    action == Action::"ShellCommandOutput",
    resource
)
when {
    context.signature.categories.contains("secrets_detection")
};

@id("forbid-data-exfiltration")
forbid (
    principal,
    action in [Action::"ShellCommand", Action::"WebFetch"],
    resource
)
when {
    context.signature.categories.contains("exfiltration")
};

@id("forbid-webfetch-with-exfiltration-taint")
forbid (
    principal,
    action == Action::"WebFetch",
    resource
)
when {
    resource.taints.contains(Taint::"exfiltration")
};

@id("forbid-webfetch-with-credential-taint")
forbid (
    principal,
    action == Action::"WebFetch",
    resource
)
when {
    resource.taints.contains(Taint::"credential_access")
};

@id("forbid-file-write-confidential-to-public")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
)
when {
    (context.label == Label::"Confidential" ||
     context.label == Label::"HighlyConfidential") &&
    (resource.label == Label::"Public" ||
     resource.label == Label::"Internal")
};

@id("forbid-command-on-tainted-trajectory")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
)
when {
    !resource.taints.isEmpty() &&
    (context.signature.categories.contains("command_injection") ||
     context.signature.categories.contains("exfiltration") ||
     context.signature.severity >= 3)
};

@id("forbid-tool-output-exfiltration-taint")
forbid (
    principal,
    action == Action::"ToolOutput",
    resource
)
when {
    resource.taints.contains(Taint::"exfiltration") &&
    context.signature.categories.contains("exfiltration")
};

@id("insider-threat-default-permit")
permit (principal, action, resource);
