@id("lol-forbid-perl-download-exec")
@description("LotL: block Perl one-liners with network capabilities — download cradle via Perl.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*perl -e *" &&
    (context.command like "*LWP::Simple*" ||
     context.command like "*IO::Socket*" ||
     context.command like "*Net::HTTP*" ||
     context.command like "*socket*")
};
