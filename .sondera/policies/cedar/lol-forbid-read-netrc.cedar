@id("lol-forbid-read-netrc")
@description("LotL: block reading .netrc files — contain plaintext credentials for network services.")
forbid (
    principal,
    action == Sondera::Action::"FileRead",
    resource
) when {
    context.path_normalized like "*/.netrc" ||
    context.path_normalized like "*/.curlrc" ||
    context.path_normalized like "*/.wgetrc"
};
