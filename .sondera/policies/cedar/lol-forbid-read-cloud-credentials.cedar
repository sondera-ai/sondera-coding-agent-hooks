@id("lol-forbid-read-cloud-credentials")
@description("LotL: block reading cloud provider credential files — prevents cloud account compromise.")
forbid (
    principal,
    action == Sondera::Action::"FileRead",
    resource
) when {
    context.path_normalized like "*/.aws/credentials" ||
    context.path_normalized like "*/.aws/config" ||
    context.path_normalized like "*/.azure/accesstokens.json" ||
    context.path_normalized like "*/.azure/azureprofile.json" ||
    context.path_normalized like "*/.config/gcloud/credentials.db" ||
    context.path_normalized like "*/.config/gcloud/application_default_credentials.json" ||
    context.path_normalized like "*/.config/gcloud/access_tokens.db" ||
    context.path_normalized like "*/.kube/config" ||
    context.path_normalized like "*/.docker/config.json"
};
