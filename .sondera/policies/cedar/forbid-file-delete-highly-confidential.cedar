@id("forbid-file-delete-highly-confidential")
@description("Block deletion of files classified as highly confidential — prevents evidence destruction.")
forbid (
    principal,
    action == Sondera::Action::"FileDelete",
    resource
) when {
    resource.label == Sondera::Label::"HighlyConfidential"
};
