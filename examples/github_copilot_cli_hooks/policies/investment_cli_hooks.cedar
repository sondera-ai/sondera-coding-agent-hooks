// Minimal investment-advisor hook policy for the Copilot CLI example.
//
// The runnable hook path uses local `sondera copilot ...` commands. This policy
// mirrors a small investment-agent posture: normal hook events are allowed, but
// destructive shell commands and sensitive account identifier exposure are
// denied in govern mode.

@id("investment-cli-hooks-default-permit")
@description("Permit normal Copilot CLI hook events unless a specific investment safety guard fires.")
permit(principal, action, resource);

@id("investment-cli-hooks-forbid-risky-shell")
@description("Block destructive commands and attempts to expose sensitive investment identifiers.")
forbid(
    principal,
    action == Action::"ShellCommand",
    resource
) when {
    context.command like "*rm -rf*" ||
    context.command like "*account_number*" ||
    context.command like "*social_security_number*" ||
    context.command like "*ssn*"
};
