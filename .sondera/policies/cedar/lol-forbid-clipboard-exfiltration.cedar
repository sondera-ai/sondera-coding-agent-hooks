@id("lol-forbid-clipboard-exfiltration")
@description("LotL: block clipboard access commands — prevents data staging via system clipboard.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*pbcopy*" ||
    context.command like "*pbpaste*" ||
    context.command like "*xclip*" ||
    context.command like "*xsel*" ||
    context.command like "*wl-copy*" ||
    context.command like "*wl-paste*"
};
