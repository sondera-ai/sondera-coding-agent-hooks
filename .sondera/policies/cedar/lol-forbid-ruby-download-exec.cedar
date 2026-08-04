@id("lol-forbid-ruby-download-exec")
@description("LotL: block Ruby one-liners with network capabilities — download cradle via Ruby.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*ruby -e *" &&
    (context.command like "*Net::HTTP*" ||
     context.command like "*open-uri*" ||
     context.command like "*TCPSocket*" ||
     context.command like "*net/http*")
};
