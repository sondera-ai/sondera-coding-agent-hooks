@id("forbid-file-write-confidential-to-public")
@description("IFC: block writing confidential content to a file labeled Public — prevents data spillage.")
forbid (
    principal,
    action in [Sondera::Action::"FileWrite", Sondera::Action::"FileEdit"],
    resource
) when {
    context.label == Sondera::Label::"Confidential" &&
    resource.label == Sondera::Label::"Public"
};
