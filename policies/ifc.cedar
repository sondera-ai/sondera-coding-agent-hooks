// ═══════════════════════════════════════════════════════
// Sondera – Information Flow Control (IFC) Policies
// ═══════════════════════════════════════════════════════
//
// Enforces lattice-based information flow control to prevent
// sensitive data from leaking through outbound channels.
//
// Model: simplified Bell-LaPadula "no write down" / "no read up"
// adapted for AI agent trajectories. Once a trajectory ingests
// data at a given sensitivity level, its label is raised to
// the max level seen (high-water mark). These policies then
// restrict which outbound actions the trajectory may perform.
//
// ─── Sensitivity Lattice ────────────────────────────────
//
//   Label::"HighlyConfidential"   (level 3) — PII, credentials, trade secrets
//   Label::"Confidential"         (level 2) — business strategy, customer data
//   Label::"Internal"             (level 1) — internal docs, meeting notes
//   Label::"Public"               (level 0) — freely shareable
//
// ─── Outbound Channels Controlled ───────────────────────
//
//   WebFetch / WebFetchOutput  — HTTP requests to external URLs
//   ShellCommand               — network tools (curl, wget, nc, ssh, scp, etc.)
//   ShellCommandOutput         — output from network commands
//
// ─── Design Principles ─────────────────────────────────
//
//   1. HighlyConfidential trajectories are fully blocked from
//      all outbound channels — no HTTP fetches, no network
//      shell commands, regardless of signatures.
//
//   2. Confidential trajectories are blocked from outbound
//      channels unless the content is clean (no signature
//      matches), providing defense-in-depth while allowing
//      legitimate development workflows.
//
//   3. Taint tracking compounds with signature detection:
//      trajectories tainted with exfiltration or credential
//      access get stricter controls at lower severity
//      thresholds.
//
//   4. Post-execution guards prevent ingesting fetched
//      content that would raise a clean trajectory's label,
//      stopping taint propagation at the boundary.

// ═══════════════════════════════════════════════════════
// §1  WebFetch – Sensitivity-Gated Outbound Blocking
// ═══════════════════════════════════════════════════════
//
// WebFetch is the primary HTTP outbound channel. An agent
// that has read highly confidential data must not make
// external HTTP requests — even "innocent" fetches could
// encode sensitive data in URLs, headers, or prompt text.

@id("ifc-forbid-webfetch-highly-confidential")
@description("IFC: block all web fetches when trajectory carries highly confidential data — unconditional outbound lockdown.")
forbid (
    principal,
    action == Action::"WebFetch",
    resource
) when {
    resource.label == Label::"HighlyConfidential"
};

@id("ifc-forbid-webfetch-confidential-with-signatures")
@description("IFC: block web fetches on confidential trajectories when YARA signatures detected — prevents data leakage via HTTP when content shows threat indicators.")
forbid (
    principal,
    action == Action::"WebFetch",
    resource
) when {
    resource.label == Label::"Confidential" &&
    context.signature.matches > 0
};

@id("ifc-forbid-webfetch-confidential-with-exfil-taint")
@description("IFC: block web fetches on confidential trajectories tainted with exfiltration — trajectory has already shown exfiltration intent.")
forbid (
    principal,
    action == Action::"WebFetch",
    resource
) when {
    resource.label == Label::"Confidential" &&
    resource.taints.contains(Taint::"exfiltration")
};

@id("ifc-forbid-webfetch-confidential-with-cred-taint")
@description("IFC: block web fetches on confidential trajectories tainted with credential access — prevents credential exfiltration via HTTP.")
forbid (
    principal,
    action == Action::"WebFetch",
    resource
) when {
    resource.label == Label::"Confidential" &&
    resource.taints.contains(Taint::"credential_access")
};

// ═══════════════════════════════════════════════════════
// §2  WebFetchOutput – Taint Propagation Guards
// ═══════════════════════════════════════════════════════
//
// Even if a WebFetch was allowed, the returned content
// could carry sensitive data back into the trajectory.
// These guards prevent escalation of the trajectory's
// sensitivity through fetched content.

@id("ifc-forbid-webfetch-output-raises-to-highly-confidential")
@description("IFC: block web fetch results classified as highly confidential — prevents taint escalation to highest level via external content.")
forbid (
    principal,
    action == Action::"WebFetchOutput",
    resource
) when {
    context.label == Label::"HighlyConfidential"
};

@id("ifc-forbid-webfetch-output-on-tainted-trajectory")
@description("IFC: block web fetch results when trajectory is already tainted with exfiltration — stops further data ingestion on compromised trajectories.")
forbid (
    principal,
    action == Action::"WebFetchOutput",
    resource
) when {
    resource.taints.contains(Taint::"exfiltration") &&
    context.signature.severity >= 2
};

@id("ifc-forbid-webfetch-output-confidential-with-secrets")
@description("IFC: block web fetch results containing secrets on confidential trajectories — prevents credential accumulation from external sources.")
forbid (
    principal,
    action == Action::"WebFetchOutput",
    resource
) when {
    resource.label == Label::"Confidential" &&
    context.signature.categories.contains("secrets_detection")
};

// ═══════════════════════════════════════════════════════
// §3  ShellCommand – Network Tool Blocking
// ═══════════════════════════════════════════════════════
//
// Shell commands that invoke network tools are an alternate
// exfiltration channel to WebFetch. Block these when the
// trajectory carries sensitive data.

@id("ifc-forbid-shell-network-highly-confidential")
@description("IFC: block network shell commands (curl, wget, ssh, scp, nc, rsync, ftp) when trajectory is highly confidential — prevents exfiltration via shell network tools.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    resource.label == Label::"HighlyConfidential" &&
    (context.command like "*curl *" ||
     context.command like "*wget *" ||
     context.command like "*ssh *" ||
     context.command like "*scp *" ||
     context.command like "*sftp *" ||
     context.command like "*rsync *" ||
     context.command like "*nc *" ||
     context.command like "*ncat *" ||
     context.command like "*netcat *" ||
     context.command like "*ftp *" ||
     context.command like "*telnet *" ||
     context.command like "*socat *")
};

@id("ifc-forbid-shell-network-confidential-with-taint")
@description("IFC: block network shell commands on confidential trajectories tainted with exfiltration — compound guard on network + exfil intent.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    resource.label == Label::"Confidential" &&
    resource.taints.contains(Taint::"exfiltration") &&
    (context.command like "*curl *" ||
     context.command like "*wget *" ||
     context.command like "*ssh *" ||
     context.command like "*scp *" ||
     context.command like "*sftp *" ||
     context.command like "*rsync *" ||
     context.command like "*nc *" ||
     context.command like "*ncat *" ||
     context.command like "*netcat *" ||
     context.command like "*ftp *")
};

@id("ifc-forbid-shell-pipe-network-highly-confidential")
@description("IFC: block shell commands piping to network tools when trajectory is highly confidential — prevents exfiltration via pipe chains.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    resource.label == Label::"HighlyConfidential" &&
    (context.command like "*| curl *" ||
     context.command like "*| wget *" ||
     context.command like "*| nc *" ||
     context.command like "*| ssh *" ||
     context.command like "*| socat *")
};

// ═══════════════════════════════════════════════════════
// §4  ShellCommandOutput – Network Output Guards
// ═══════════════════════════════════════════════════════
//
// Guard the output side of network commands to detect
// successful exfiltration or ingestion of sensitive data
// from external sources.

@id("ifc-forbid-shell-output-secrets-on-sensitive-trajectory")
@description("IFC: block shell output containing secrets when trajectory carries confidential or higher data — prevents credential accumulation on sensitive trajectories.")
forbid (
    principal,
    action == Action::"ShellCommandOutput",
    resource
) when {
    (resource.label == Label::"Confidential" ||
     resource.label == Label::"HighlyConfidential") &&
    context.signature.categories.contains("secrets_detection")
};

@id("ifc-forbid-shell-output-raises-to-highly-confidential")
@description("IFC: block shell command output classified as highly confidential — prevents taint escalation via command results.")
forbid (
    principal,
    action == Action::"ShellCommandOutput",
    resource
) when {
    context.label == Label::"HighlyConfidential" &&
    resource.label != Label::"HighlyConfidential"
};

// ═══════════════════════════════════════════════════════
// §5  Trajectory Step Limits – Sensitivity-Scaled
// ═══════════════════════════════════════════════════════
//
// Limit how many outbound actions a sensitive trajectory
// can take. More sensitive data = tighter step budget.
// This bounds the blast radius even if individual actions
// are permitted.

@id("ifc-forbid-confidential-trajectory-runaway")
@description("IFC: limit confidential trajectories to 100 outbound steps — bounds blast radius of data exposure.")
forbid (
    principal,
    action in [Action::"ShellCommand", Action::"WebFetch"],
    resource
) when {
    resource.label == Label::"Confidential" &&
    resource.step_count > 100
};

@id("ifc-forbid-highly-confidential-trajectory-strict-limit")
@description("IFC: limit highly confidential trajectories to 25 outbound steps — strict bound on highest-sensitivity processing.")
forbid (
    principal,
    action in [Action::"ShellCommand", Action::"WebFetch"],
    resource
) when {
    resource.label == Label::"HighlyConfidential" &&
    resource.step_count > 25
};

// ═══════════════════════════════════════════════════════
// §6  Cross-Channel Compound Guards
// ═══════════════════════════════════════════════════════
//
// Policies that combine sensitivity labels with multiple
// threat indicators to catch sophisticated exfiltration
// that might evade single-signal detection.

@id("ifc-forbid-sensitive-trajectory-with-obfuscation")
@description("IFC: block any outbound action on sensitive trajectories when obfuscation detected — obfuscation + sensitive data is a strong exfiltration signal.")
forbid (
    principal,
    action in [Action::"ShellCommand", Action::"WebFetch"],
    resource
) when {
    (resource.label == Label::"Confidential" ||
     resource.label == Label::"HighlyConfidential") &&
    context.signature.categories.contains("obfuscation")
};

@id("ifc-forbid-sensitive-trajectory-defense-evasion")
@description("IFC: block outbound actions on sensitive trajectories using defense evasion techniques — encoding, steganography, or homoglyphs in outbound content.")
forbid (
    principal,
    action in [Action::"ShellCommand", Action::"WebFetch"],
    resource
) when {
    (resource.label == Label::"Confidential" ||
     resource.label == Label::"HighlyConfidential") &&
    context.signature.categories.contains("defense_evasion")
};

@id("ifc-forbid-tool-output-on-highly-confidential-trajectory")
@description("IFC: block generic tool output processing on highly confidential trajectories when threats detected — prevents data ingestion from untrusted tool results.")
forbid (
    principal,
    action == Action::"ToolOutput",
    resource
) when {
    resource.label == Label::"HighlyConfidential" &&
    context.signature.matches > 0
};
