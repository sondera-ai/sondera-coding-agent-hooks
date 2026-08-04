// Block exfiltration attempts to package registries
// Prevents credential stealing via package registry access
@id("forbid-suspicious-registry-fetch-exfiltration")
@description("Block exfiltration attempts targeting package registries (pypi, npm, crates.io, rubygems).")
forbid (
    principal,
    action == Sondera::Action::"WebFetch",
    resource
)
when {
    context.signature.categories.contains("exfiltration") &&
    context has url_parse &&
    context.url_parse.ok &&
    (context.url_parse.host == "pypi.org" ||
     context.url_parse.host like "*.pypi.org" ||
     context.url_parse.host == "npmjs.org" ||
     context.url_parse.host like "*.npmjs.org" ||
     context.url_parse.host == "crates.io" ||
     context.url_parse.host like "*.crates.io" ||
     context.url_parse.host == "rubygems.org" ||
     context.url_parse.host like "*.rubygems.org" ||
     context.url_parse.host == "npmjs.com" ||
     context.url_parse.host like "*.npmjs.com") &&
    context.signature.severity >= 3
};
