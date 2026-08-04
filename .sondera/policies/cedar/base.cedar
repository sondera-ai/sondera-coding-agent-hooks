// Sondera base governance policies for coding agents.
//
// The harness populates Cedar contexts in
// `crates/policy/cedar/src/transform.rs`. Cedar evaluates all matching
// policies, and any matching forbid overrides this default permit.
//
// Actions and context:
//
//   Sondera::Action::"Prompt"
//     resource = Message
//     context  = { workspace, signature, label }
//
//   Sondera::Action::"PreToolUse"
//     resource = Tool
//     context  = { workspace, signature, policy, label, tool, arguments }
//
//   Sondera::Action::"ShellCommand"
//     resource = Trajectory
//     context  = { workspace, signature, file_signature, policy, label,
//                  command, working_dir, parse }
//
//   Sondera::Action::"ShellCommandOutput"
//     resource = Trajectory
//     context  = { workspace, signature, policy, label, command, exit_code,
//                  stdout, stderr, working_dir }
//
//   Sondera::Action::"WebFetch"
//     resource = Trajectory
//     context  = { workspace, signature, policy, label, url, prompt, url_parse }
//
//   Sondera::Action::"WebFetchOutput"
//     resource = Trajectory
//     context  = { workspace, signature, policy, label, url, code, result }
//
//   Sondera::Action::"FileRead" / "FileWrite" / "FileEdit" / "FileDelete"
//     resource = File
//     context  = { workspace, signature, policy, label, path, operation }
//
//   Sondera::Action::"FileOperationResult"
//     resource = Trajectory
//     context  = { workspace, signature, policy, label, path, content }
//
//   Sondera::Action::"ToolOutput"
//     resource = Trajectory
//     context  = { workspace, signature, policy, label, content }
//
// Shared context records and resource attributes are defined in
// `base.cedarschema`.

@id("default-permit")
@description("Permit all actions unless a forbid below fires.")
permit (principal, action, resource);
