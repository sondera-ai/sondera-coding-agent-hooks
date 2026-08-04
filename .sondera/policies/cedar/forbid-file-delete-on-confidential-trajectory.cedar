@id("forbid-file-delete-on-confidential-trajectory")
@description("Block all file deletions when trajectory carries confidential or higher data — prevents evidence destruction.")
forbid (
    principal,
    action == Sondera::Action::"FileDelete",
    resource
) when {
    context.label == Sondera::Label::"Confidential" ||
    context.label == Sondera::Label::"HighlyConfidential"
};
