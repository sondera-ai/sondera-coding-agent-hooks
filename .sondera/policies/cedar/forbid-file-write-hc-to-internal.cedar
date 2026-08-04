@id("forbid-file-write-hc-to-internal")
@description("IFC: block writing highly confidential content to a file labeled Internal — prevents data spillage.")
forbid (
    principal,
    action in [Sondera::Action::"FileWrite", Sondera::Action::"FileEdit"],
    resource
) when {
    context.label == Sondera::Label::"HighlyConfidential" &&
    resource.label == Sondera::Label::"Internal"
};
