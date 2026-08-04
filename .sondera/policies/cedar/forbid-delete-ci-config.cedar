@id("forbid-delete-ci-config")
@description("Block deletion of CI/CD configuration files — breaks automated build and deploy pipelines.")
forbid (
    principal,
    action == Sondera::Action::"FileDelete",
    resource
) when {
    context.path_normalized like "*.github/workflows/*.yml" ||
    context.path_normalized like "*.github/workflows/*.yaml" ||
    context.path_normalized like "*.gitlab-ci.yml" ||
    context.path_normalized like "*jenkinsfile" ||
    context.path_normalized like "*.circleci/config.yml"
};
