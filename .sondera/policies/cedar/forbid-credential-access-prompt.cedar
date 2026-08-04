@id("forbid-credential-access-prompt")
@description("Block prompts that attempt to access or extract credentials.")
forbid (
    principal,
    action == Sondera::Action::"Prompt",
    resource
) when {
    context.signature.categories.contains("credential_access")
};
