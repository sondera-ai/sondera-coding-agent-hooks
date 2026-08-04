@id("lol-forbid-audit-tampering")
@description("LotL: block modification of audit configuration — prevents disabling of audit trail.")
forbid (
    principal,
    action in [Sondera::Action::"FileWrite", Sondera::Action::"FileEdit"],
    resource
) when {
    context.path_normalized like "*/etc/audit/*" ||
    context.path_normalized like "*/etc/rsyslog*" ||
    context.path_normalized like "*/etc/syslog*" ||
    context.path_normalized like "*/etc/logrotate*"
};
