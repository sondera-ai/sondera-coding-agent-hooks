@id("lol-forbid-security-tool-tampering")
@description("LotL: block disabling of security tools and firewalls — defense evasion via tool suppression.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*systemctl stop *firewall*" ||
    context.command like "*systemctl disable *firewall*" ||
    context.command like "*ufw disable*" ||
    context.command like "*iptables -F*" ||
    context.command like "*iptables -X*" ||
    context.command like "*setenforce 0*" ||
    context.command like "*pfctl -d*" ||
    context.command like "*csrutil disable*" ||
    context.command like "*spctl --master-disable*" ||
    context.command like "*xattr -d com.apple.quarantine*"
};
