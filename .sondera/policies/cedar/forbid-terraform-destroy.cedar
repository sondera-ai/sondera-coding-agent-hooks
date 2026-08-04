@id("forbid-terraform-destroy")
@description("Block terraform destroy — tears down all managed infrastructure.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*terraform destroy*" ||
    context.command like "*tofu destroy*"
};
