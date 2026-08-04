@id("lol-forbid-read-shell-history")
@description("LotL: block reading shell history files — may contain previously typed credentials and tokens.")
forbid (
    principal,
    action == Sondera::Action::"FileRead",
    resource
) when {
    context.path_normalized like "*/.bash_history" ||
    context.path_normalized like "*/.zsh_history" ||
    context.path_normalized like "*/.history" ||
    context.path_normalized like "*/.python_history" ||
    context.path_normalized like "*/.node_repl_history" ||
    context.path_normalized like "*/.psql_history" ||
    context.path_normalized like "*/.mysql_history" ||
    context.path_normalized like "*/.rediscli_history"
};
