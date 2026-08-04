@id("forbid-kubectl-delete-all")
@description("Block kubectl delete with --all flag — mass-deletes Kubernetes resources.")
forbid (
    principal,
    action == Sondera::Action::"ShellCommand",
    resource
) when {
    context.command like "*kubectl delete * --all*"
};
