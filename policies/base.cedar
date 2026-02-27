// ═══════════════════════════════════════════════════════
// Sondera – Base Governance Policies for Coding Agents
// ═══════════════════════════════════════════════════════
//
// Applies to all coding agents (Claude Code, Cursor, Copilot, etc.).
//
// Strategy: default-permit with targeted forbid overrides.
// Cedar evaluates all policies; a single matching forbid wins.
//
// ─── Actions & Context ────────────────────────────────
//
// Each action is evaluated with a context populated by the
// harness (see cedar/transform.rs). Available actions and
// their context fields:
//
//   Action::"Prompt"
//     resource  = Message (in Trajectory)
//     context   = { workspace, signature, label }
//     Fires on user/system prompt submission. Content is
//     scanned for YARA signatures and classified for
//     data sensitivity. The trajectory's label is raised
//     to the max sensitivity seen so far.
//
//   Action::"ShellCommand"
//     resource  = Trajectory
//     context   = { workspace, signature, policy, label,
//                   command, working_dir }
//     Fires before shell command execution. The command
//     string is scanned for signatures, classified for
//     sensitivity, and evaluated against the policy model.
//
//   Action::"ShellCommandOutput"
//     resource  = Trajectory
//     context   = { workspace, signature, policy, label,
//                   command, exit_code, stdout, stderr,
//                   working_dir }
//     Fires after shell command execution. Combined
//     stdout+stderr is scanned, classified, and evaluated.
//     The trajectory label is raised if output contains
//     higher-sensitivity data.
//
//   Action::"WebFetch"
//     resource  = Trajectory
//     context   = { workspace, signature, policy, label,
//                   url, prompt }
//     Fires before a web fetch operation. The URL and
//     prompt are scanned for signatures, classified for
//     sensitivity, and evaluated against the policy model.
//
//   Action::"WebFetchOutput"
//     resource  = Trajectory
//     context   = { workspace, signature, policy, label,
//                   url, code, result }
//     Fires after a web fetch completes. The result
//     content is scanned, classified, and evaluated.
//     The trajectory label is raised if the fetched
//     content contains higher-sensitivity data.
//
//   Action::"FileRead" / "FileWrite" / "FileEdit" / "FileDelete"
//     resource  = File
//     context   = { workspace, signature, policy, label,
//                   path, operation }
//     Fires before a file operation. The path and content
//     are scanned, classified, and evaluated. A forbid
//     here prevents the operation.
//
//   Action::"FileOperationResult"
//     resource  = Trajectory
//     context   = { workspace, signature, policy, label,
//                   path, content }
//     Fires after a file operation completes. Content is
//     scanned and classified. The trajectory label is
//     raised if the file contains higher-sensitivity data.
//
// ─── Shared Context Types ─────────────────────────────
//
//   workspace  = { cwd, permission_mode, transcript_path }
//   signature  = { matches: Long, categories: Set<String>,
//                  severity: Long }
//                  Severity: 0=None 1=Low 2=Medium 3=High 4=Critical
//   policy     = { compliant: Bool, violations: Set<String> }
//   label      = Label entity (e.g. Label::"HighlyConfidential")

// ─── Baseline ───────────────────────────────────────

@id("default-permit")
@description("Permit all actions unless a forbid below fires.")
permit (principal, action, resource);

// ═══════════════════════════════════════════════════════
// §1  Prompt – Signature-Based Threat Detection
// ═══════════════════════════════════════════════════════
//
// Guard the Prompt action by blocking user or system
// prompts whose content triggers YARA signature rules.

@id("forbid-critical-severity")
@description("Block any prompt where YARA signatures flagged critical severity (4).")
forbid (
    principal,
    action == Action::"Prompt",
    resource
) when {
    context.signature.severity >= 4
};

@id("forbid-prompt-injection")
@description("Block prompts containing prompt injection patterns (role manipulation, system override, ignore instructions).")
forbid (
    principal,
    action == Action::"Prompt",
    resource
) when {
    context.signature.categories.contains("prompt_injection")
};

@id("forbid-indirect-injection")
@description("Block prompts containing indirect injection via embedded document instructions.")
forbid (
    principal,
    action == Action::"Prompt",
    resource
) when {
    context.signature.categories.contains("indirect_injection")
};

@id("forbid-credential-access-prompt")
@description("Block prompts that attempt to access or extract credentials.")
forbid (
    principal,
    action == Action::"Prompt",
    resource
) when {
    context.signature.categories.contains("credential_access")
};

@id("forbid-data-exfiltration-prompt")
@description("Block prompts with data exfiltration patterns.")
forbid (
    principal,
    action == Action::"Prompt",
    resource
) when {
    context.signature.categories.contains("exfiltration")
};

@id("forbid-command-injection-prompt")
@description("Block prompts containing command injection patterns.")
forbid (
    principal,
    action == Action::"Prompt",
    resource
) when {
    context.signature.categories.contains("command_injection")
};

@id("forbid-defense-evasion-prompt")
@description("Block prompts using obfuscation to evade detection (base64, HTML entities, homoglyphs).")
forbid (
    principal,
    action == Action::"Prompt",
    resource
) when {
    context.signature.categories.contains("defense_evasion")
};

@id("forbid-tool-abuse-prompt")
@description("Block prompts attempting to abuse agent tools via injection.")
forbid (
    principal,
    action == Action::"Prompt",
    resource
) when {
    context.signature.categories.contains("tool_abuse")
};

// ═══════════════════════════════════════════════════════
// §2  Prompt – Sensitivity-Gated Controls
// ═══════════════════════════════════════════════════════
//
// Combine the data sensitivity label (IFC classifier)
// with signature detection to enforce stricter controls
// on sensitive data.

@id("forbid-highly-confidential-with-threats")
@description("Block prompts on highly confidential data when any YARA signature matched.")
forbid (
    principal,
    action == Action::"Prompt",
    resource
) when {
    context.label == Label::"HighlyConfidential" &&
    context.signature.matches > 0
};

@id("forbid-confidential-high-severity")
@description("Block prompts on confidential data when YARA severity is high or above.")
forbid (
    principal,
    action == Action::"Prompt",
    resource
) when {
    context.label == Label::"Confidential" &&
    context.signature.severity >= 3
};

// ═══════════════════════════════════════════════════════
// §3  Shell Command – Pre-Execution Gates
// ═══════════════════════════════════════════════════════
//
// Block dangerous commands before they execute. The
// policy model and YARA signatures evaluate the command
// string. A forbid here prevents execution entirely.

@id("forbid-shell-policy-violation")
@description("Block shell commands that violate the policy model (destructive, unsafe, etc.).")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    !context.policy.compliant
};

@id("forbid-shell-command-injection")
@description("Block shell commands containing injection patterns (chaining, reverse shells, cron manipulation).")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.signature.categories.contains("command_injection")
};

@id("forbid-shell-obfuscation")
@description("Block shell commands using obfuscation to hide intent (base64, hex, concatenation).")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.signature.categories.contains("obfuscation")
};

@id("forbid-shell-exfiltration")
@description("Block shell commands with data exfiltration patterns (curl to paste sites, DNS tunneling).")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.signature.categories.contains("exfiltration")
};

@id("forbid-shell-credential-access")
@description("Block shell commands accessing sensitive credential files or cloud configs.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.signature.categories.contains("credential_access")
};

@id("forbid-shell-critical-severity")
@description("Block shell commands that trigger critical-severity YARA rules.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.signature.severity >= 4
};

// ─── IFC: prevent exfiltration of sensitive data via shell ───

@id("forbid-shell-highly-confidential")
@description("Block shell commands when trajectory carries highly confidential data — prevents exfiltration via shell.")
forbid (
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.label == Label::"HighlyConfidential" &&
    context.signature.categories.contains("exfiltration")
};

// ═══════════════════════════════════════════════════════
// §4  Shell Command Output – Post-Execution Guards
// ═══════════════════════════════════════════════════════
//
// Detect threats in command output. A forbid here signals
// the harness to halt the trajectory when output reveals
// secrets, credentials, or exfiltration artifacts.

@id("forbid-shell-output-secrets")
@description("Block when command output contains detected secrets (API keys, tokens, private keys).")
forbid (
    principal,
    action == Action::"ShellCommandOutput",
    resource
) when {
    context.signature.categories.contains("secrets_detection")
};

@id("forbid-shell-output-credential-leak")
@description("Block when command output exposes credentials (memory dumps, cloud creds).")
forbid (
    principal,
    action == Action::"ShellCommandOutput",
    resource
) when {
    context.signature.categories.contains("credential_access")
};

@id("forbid-shell-output-policy-violation")
@description("Block when command output violates the policy model.")
forbid (
    principal,
    action == Action::"ShellCommandOutput",
    resource
) when {
    !context.policy.compliant
};

@id("forbid-shell-output-exfiltration-evidence")
@description("Block when command output shows evidence of data exfiltration (network sends, paste site responses).")
forbid (
    principal,
    action == Action::"ShellCommandOutput",
    resource
) when {
    context.signature.categories.contains("exfiltration")
};

// ═══════════════════════════════════════════════════════
// §5  Web Fetch – Pre-Execution Gates
// ═══════════════════════════════════════════════════════
//
// Block web requests before they fire. Guards against
// exfiltration via HTTP, fetching from malicious domains,
// and data leakage of sensitive content.

@id("forbid-webfetch-policy-violation")
@description("Block web fetches that violate the policy model.")
forbid (
    principal,
    action == Action::"WebFetch",
    resource
) when {
    !context.policy.compliant
};

@id("forbid-webfetch-exfiltration")
@description("Block web fetches to exfiltration targets (paste sites, suspicious external domains).")
forbid (
    principal,
    action == Action::"WebFetch",
    resource
) when {
    context.signature.categories.contains("exfiltration")
};

@id("forbid-webfetch-obfuscation")
@description("Block web fetches using obfuscated URLs or prompts to evade detection.")
forbid (
    principal,
    action == Action::"WebFetch",
    resource
) when {
    context.signature.categories.contains("obfuscation")
};

@id("forbid-webfetch-critical-severity")
@description("Block web fetches that trigger critical-severity YARA rules.")
forbid (
    principal,
    action == Action::"WebFetch",
    resource
) when {
    context.signature.severity >= 4
};

// ─── IFC: prevent data leakage via web requests ───

@id("forbid-webfetch-highly-confidential")
@description("Block all web fetches when trajectory is tainted with highly confidential data — prevents HTTP exfiltration.")
forbid (
    principal,
    action == Action::"WebFetch",
    resource
) when {
    resource.label == Label::"HighlyConfidential" &&
    context.signature.matches > 0
};

// ═══════════════════════════════════════════════════════
// §6  Web Fetch Output – Post-Execution Guards
// ═══════════════════════════════════════════════════════
//
// Detect threats in fetched web content before the agent
// processes it further.

@id("forbid-webfetch-output-injection")
@description("Block web fetch results containing prompt injection patterns — prevents indirect injection via web content.")
forbid (
    principal,
    action == Action::"WebFetchOutput",
    resource
) when {
    context.signature.categories.contains("prompt_injection") ||
    context.signature.categories.contains("indirect_injection")
};

@id("forbid-webfetch-output-secrets")
@description("Block web fetch results that contain detected secrets.")
forbid (
    principal,
    action == Action::"WebFetchOutput",
    resource
) when {
    context.signature.categories.contains("secrets_detection")
};

@id("forbid-webfetch-output-critical")
@description("Block web fetch results with critical-severity YARA matches.")
forbid (
    principal,
    action == Action::"WebFetchOutput",
    resource
) when {
    context.signature.severity >= 4
};

// ═══════════════════════════════════════════════════════
// §7  File Operations – Pre-Execution Gates
// ═══════════════════════════════════════════════════════
//
// Guard file read/write/edit/delete before execution.
// Resource is the File entity with its sensitivity label.

@id("forbid-file-policy-violation")
@description("Block file operations that violate the policy model.")
forbid (
    principal,
    action in [Action::"FileRead", Action::"FileWrite", Action::"FileEdit", Action::"FileDelete"],
    resource
) when {
    !context.policy.compliant
};

@id("forbid-file-credential-access")
@description("Block file operations on sensitive credential and config files (.env, private keys, cloud creds).")
forbid (
    principal,
    action in [Action::"FileRead", Action::"FileWrite", Action::"FileEdit", Action::"FileDelete"],
    resource
) when {
    context.signature.categories.contains("credential_access")
};

@id("forbid-file-write-secrets")
@description("Block file writes or edits that would embed secrets into source code.")
forbid (
    principal,
    action in [Action::"FileWrite", Action::"FileEdit"],
    resource
) when {
    context.signature.categories.contains("secrets_detection")
};

@id("forbid-file-path-traversal")
@description("Block file operations with path traversal patterns in the file path.")
forbid (
    principal,
    action in [Action::"FileRead", Action::"FileWrite", Action::"FileEdit", Action::"FileDelete"],
    resource
) when {
    context.signature.categories.contains("command_injection")
};

@id("forbid-file-delete-highly-confidential")
@description("Block deletion of files classified as highly confidential — prevents evidence destruction.")
forbid (
    principal,
    action == Action::"FileDelete",
    resource
) when {
    resource.label == Label::"HighlyConfidential"
};

@id("forbid-file-critical-severity")
@description("Block file operations that trigger critical-severity YARA rules.")
forbid (
    principal,
    action in [Action::"FileRead", Action::"FileWrite", Action::"FileEdit", Action::"FileDelete"],
    resource
) when {
    context.signature.severity >= 4
};

// ═══════════════════════════════════════════════════════
// §8  File Operation Result – Post-Execution Guards
// ═══════════════════════════════════════════════════════
//
// Detect threats in file content after reads complete
// and before the agent acts on the data.

@id("forbid-file-result-secrets")
@description("Block when file content reveals secrets — prevents the agent from using exposed credentials.")
forbid (
    principal,
    action == Action::"FileOperationResult",
    resource
) when {
    context.signature.categories.contains("secrets_detection") &&
    context.signature.severity >= 3
};

@id("forbid-file-result-injection")
@description("Block when file content contains prompt injection — prevents indirect injection via file reads.")
forbid (
    principal,
    action == Action::"FileOperationResult",
    resource
) when {
    context.signature.categories.contains("prompt_injection") ||
    context.signature.categories.contains("indirect_injection")
};

@id("forbid-file-result-policy-violation")
@description("Block when file operation results violate the policy model.")
forbid (
    principal,
    action == Action::"FileOperationResult",
    resource
) when {
    !context.policy.compliant
};

// ═══════════════════════════════════════════════════════
// §9  Trajectory-Level Controls – Runaway Agent Protection
// ═══════════════════════════════════════════════════════
//
// Guard against runaway agents by limiting trajectory
// step counts when the trajectory is tainted with
// sensitive data. These apply to any action targeting
// a Trajectory resource.

@id("forbid-tainted-trajectory-runaway")
@description("Limit highly confidential trajectories to 50 steps — prevents unbounded processing of sensitive data.")
forbid (
    principal,
    action in [Action::"ShellCommand", Action::"WebFetch"],
    resource
) when {
    resource.label == Label::"HighlyConfidential" &&
    resource.step_count > 50
};

@id("forbid-tainted-trajectory-with-threats")
@description("Block further actions on tainted trajectories when signatures detect active threats.")
forbid (
    principal,
    action in [Action::"ShellCommand", Action::"ShellCommandOutput", Action::"WebFetch", Action::"WebFetchOutput", Action::"FileOperationResult"],
    resource
) when {
    resource.taints.contains(Taint::"exfiltration") &&
    context.signature.matches > 0
};
