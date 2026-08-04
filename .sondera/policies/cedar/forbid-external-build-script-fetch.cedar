// Block exfiltration attempts when fetching build scripts
// Prevents malicious download and execution of remote build scripts
@id("forbid-external-build-script-fetch")
@description("Block exfiltration attempts when fetching remote build scripts (setup.py, Makefile, configure).")
forbid (
    principal,
    action == Sondera::Action::"WebFetch",
    resource
)
when {
    (context.prompt like "*setup.py*" ||
     context.prompt like "*build script*" ||
     context.prompt like "*Makefile*" ||
     context.prompt like "*configure*") &&
    context.signature.categories.contains("exfiltration")
};
