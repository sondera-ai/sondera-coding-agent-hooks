@id("lol-forbid-xxd-od-encoding")
@description("LotL: block hex dump tools on sensitive paths — alternate encoding for data staging.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    (context.command like "*xxd *" || context.command like "*od -A x *") &&
    (context.command like "*/.ssh*" ||
     context.command like "*/.aws*" ||
     context.command like "*/.env*" ||
     context.command like "*/etc/shadow*" ||
     context.command like "*secret*" ||
     context.command like "*credential*" ||
     context.command like "*token*")
};
