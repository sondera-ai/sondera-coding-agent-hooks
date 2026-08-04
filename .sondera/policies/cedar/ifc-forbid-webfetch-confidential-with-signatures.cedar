// Block only on High or Critical signatures. Severity values are:
// None=0, Low=1, Medium=2, High=3, Critical=4.
@id("ifc-forbid-webfetch-confidential-with-signatures")
@description("Block web fetches from confidential trajectories when YARA detects critical or high-severity threat indicators.")
forbid (
    principal,
    action == Sondera::Action::"WebFetch",
    resource
) when {
    resource.label == Sondera::Label::"Confidential" &&
    context.signature.severity > 2
};
