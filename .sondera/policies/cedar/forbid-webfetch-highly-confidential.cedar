@id("forbid-webfetch-highly-confidential")
@description("Block all web fetches when trajectory is labeled highly confidential — prevents HTTP exfiltration.")
forbid (
    principal,
    action == Sondera::Action::"WebFetch",
    resource
) when {
    resource.label == Sondera::Label::"HighlyConfidential" &&
    context.signature.matches > 0
};
