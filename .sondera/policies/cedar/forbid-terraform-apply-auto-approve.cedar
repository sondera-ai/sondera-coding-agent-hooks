@id("forbid-terraform-apply-auto-approve")
@description("Block terraform apply with auto-approve — bypasses human review of infrastructure changes.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*terraform apply -auto-approve*" ||
    context.command like "*terraform apply --auto-approve*" ||
    context.command like "*tofu apply -auto-approve*" ||
    context.command like "*tofu apply --auto-approve*"
};
