use super::entity::{EntityBuilder, Trajectory, euid};
use super::{CedarPolicyHarness, path_normalize, shell_parse, url_parse};
use anyhow::Result;
use cedar_policy::{Context, EntityUid, Request};
use serde::Serialize;
use sondera_information_flow_control::Label;
use sondera_policy::{PolicyClassification, PolicyModel};
use sondera_types::EntityReaderWriter;
use sondera_types::{
    Action, Adjudicated, Decision, Event, Observation, PolicyMetadata, TrajectoryEvent,
};
use std::collections::BTreeSet;
use std::time::Duration;
use tracing::{debug, warn};

#[derive(Debug, Clone, Serialize, PartialEq)]
struct WorkspaceContext {
    cwd: String,
}

/// The policy-classifier half of a Cedar request context.
///
/// `violations` carries category *codes* (`"SC2"`), not the human-readable
/// category names: the codes are the closed set `policies.toml` declares and the
/// MCP authoring server serves, so they are what a Cedar condition can match
/// exactly. Ordered so the same classification always serializes identically.
#[derive(Debug, Serialize, PartialEq)]
struct PolicyContext {
    compliant: bool,
    violations: BTreeSet<String>,
}

impl PolicyContext {
    /// The context for content no classifier judged.
    ///
    /// Also the fail-open value, so a policy keyed on
    /// `context.policy.violations` does not fire when the classifier is off,
    /// unreachable, or slow.
    fn unjudged() -> Self {
        Self {
            compliant: true,
            violations: BTreeSet::new(),
        }
    }
}

impl From<PolicyClassification> for PolicyContext {
    fn from(classification: PolicyClassification) -> Self {
        Self {
            compliant: classification.compliant,
            violations: classification.codes(),
        }
    }
}

fn workspace_context(event: &Event) -> WorkspaceContext {
    let cwd = match &event.event {
        TrajectoryEvent::Action(Action::ShellCommand(command)) => {
            command.working_dir.clone().unwrap_or_default()
        }
        _ => String::new(),
    };
    WorkspaceContext { cwd }
}

/// Ceiling on one classification, whichever guardrail runs it.
///
/// Both classifiers pick their own internal budget —
/// [`PolicyModel::evaluate_content`] allows 30 seconds per template — which is a
/// batch-evaluation figure, not an in-loop one. This is the adjudication path and
/// an agent is blocked on it, so the outer budget is the one that decides, and
/// both are held to the same one.
const CLASSIFY_TIMEOUT: Duration = Duration::from_secs(5);

async fn classify_label(
    model: Option<&sondera_information_flow_control::DataModel>,
    content: &str,
) -> Label {
    let Some(model) = model else {
        return Label::Public;
    };
    if content.is_empty() {
        return Label::Public;
    }

    match tokio::time::timeout(CLASSIFY_TIMEOUT, model.classify(content)).await {
        Ok(Ok(classification)) => classification.max_label(),
        Ok(Err(error)) => {
            warn!(error = %error, "IFC classification failed; defaulting to Public");
            Label::Public
        }
        Err(_) => {
            warn!(
                timeout_ms = CLASSIFY_TIMEOUT.as_millis() as u64,
                "IFC classification timed out; defaulting to Public"
            );
            Label::Public
        }
    }
}

/// Classify content against the configured policy templates.
///
/// Fails open on every degraded path — classifier disabled, empty content,
/// provider error, timeout — for the same reason [`classify_label`] fails open to
/// `Public`: a classifier that cannot answer must not synthesize a violation,
/// since the deny that followed would name a category the content was never
/// judged against. What that costs a policy author is the served authoring
/// guide's to explain, and it does.
async fn classify_policy(model: Option<&PolicyModel>, content: &str) -> PolicyContext {
    let Some(model) = model else {
        return PolicyContext::unjudged();
    };
    if content.is_empty() {
        return PolicyContext::unjudged();
    }

    match tokio::time::timeout(CLASSIFY_TIMEOUT, model.evaluate_content(content)).await {
        Ok(Ok(classification)) => classification.into(),
        Ok(Err(error)) => {
            warn!(error = %error, "Policy classification failed; defaulting to compliant");
            PolicyContext::unjudged()
        }
        Err(_) => {
            warn!(
                timeout_ms = CLASSIFY_TIMEOUT.as_millis() as u64,
                "Policy classification timed out; defaulting to compliant"
            );
            PolicyContext::unjudged()
        }
    }
}

impl CedarPolicyHarness {
    /// Classify one piece of content with both model guardrails.
    ///
    /// Joined rather than sequenced: they are independent provider round-trips
    /// over the same content, and an agent is blocked on both, so the worst case
    /// is one [`CLASSIFY_TIMEOUT`] instead of two. Every action whose context
    /// declares `policy` classifies through here; `Prompt`, which declares none,
    /// calls [`classify_label`] alone.
    async fn classify(&self, content: &str) -> (Label, PolicyContext) {
        tokio::join!(
            classify_label(self.data_model.as_ref(), content),
            classify_policy(self.policy_model.as_ref(), content),
        )
    }

    /// Raise the trajectory's sensitivity label monotonically.
    ///
    /// The compare happens against the *stored* label rather than a copy read
    /// earlier in this request, so a label raised concurrently is never
    /// silently reverted.
    async fn mark_trajectory_label(&self, trajectory_uid: &EntityUid, label: Label) -> Result<()> {
        self.store
            .update_entity(trajectory_uid, |existing| {
                let Some(entity) = existing else {
                    return Ok(None);
                };
                let mut trajectory = Trajectory::try_from(entity)?;
                if label.level() <= trajectory.label.level() {
                    return Ok(None);
                }
                debug!(
                    "Marking trajectory: {:?} with label: {:?}",
                    &trajectory.trajectory_id, label
                );
                trajectory.label = label;
                Ok(Some(trajectory.into_entity()?))
            })
            .await
    }

    /// Build a Cedar authorization request from an Event.
    pub(super) async fn build_request(&self, event: &Event) -> Result<Request> {
        let workspace_ctx = workspace_context(event);
        let principal_id = euid("Agent", &event.actor.id)?;
        let trajectory_id = euid("Trajectory", &event.trajectory_id)?;

        // Create-if-absent and count this step. Both trajectory mutations here
        // go through `update` so a concurrent adjudication on the same
        // trajectory cannot interleave its own whole-entity write between our
        // read and our write and lose the other's update.
        self.store
            .update_entity(&trajectory_id, |existing| {
                let mut trajectory = match existing {
                    Some(entity) => Trajectory::try_from(entity)?,
                    None => {
                        debug!(
                            "Trajectory {:?} not found, creating new.",
                            &event.trajectory_id
                        );
                        Trajectory::new(&event.trajectory_id)
                    }
                };
                trajectory.step_count += 1;
                Ok(Some(trajectory.into_entity()?))
            })
            .await?;

        // The match arms below move `trajectory_id` into the Cedar request, so
        // the label-raising calls keep their own handle.
        let trajectory_uid = trajectory_id.clone();

        let (action_id, resource_id, context) = match &event.event {
            TrajectoryEvent::Observation(Observation::Prompt(prompt)) => {
                let message_id = euid("Message", &event.event_id)?;

                // Build signature context from prompt content.
                let sig = sondera_signature::scan(&prompt.content);
                let severity: i64 = sig.severity.into();
                let categories: Vec<&str> = sig.categories.iter().map(|s| s.as_str()).collect();

                // Get the max sensitivity label of Message.
                let label = classify_label(self.data_model.as_ref(), &prompt.content).await;
                let label_id = euid("Label", &label.to_string())?;

                // Build Message entity and add to store.
                let message = EntityBuilder::new(message_id)
                    .parent_uid(trajectory_id)
                    .string("content", &prompt.content)
                    .string("role", &prompt.role.to_string().to_lowercase())
                    .build()?;
                self.store.upsert(&message).await?;

                self.mark_trajectory_label(&trajectory_uid, label).await?;

                // Build up Cedar request context.
                let context_value = serde_json::json!({
                    "workspace": workspace_ctx,
                    "label": label_id.to_json_value()?,
                    "signature": {
                        "matches": sig.matches.len() as i64,
                        "categories": categories,
                        "severity": severity,
                    }
                });
                let context = Context::from_json_value(context_value, None)?;
                (
                    euid("Action", "Prompt")?,
                    euid("Message", &event.event_id)?,
                    context,
                )
            }
            TrajectoryEvent::Action(Action::ToolCall(tc)) => {
                let arguments = serde_json::to_string(&tc.arguments)?;
                let content = format!("{}\n{}", tc.tool, arguments);
                let sig = sondera_signature::scan(&content);
                let severity: i64 = sig.severity.into();
                let categories: Vec<&str> = sig.categories.iter().map(String::as_str).collect();
                let (label, policy) = self.classify(&content).await;
                let label_id = euid("Label", &label.to_string())?;
                self.mark_trajectory_label(&trajectory_uid, label).await?;

                let context = Context::from_json_value(
                    serde_json::json!({
                        "workspace": workspace_ctx,
                        "tool": tc.tool,
                        "arguments": arguments,
                        "label": label_id.to_json_value()?,
                        "policy": policy,
                        "signature": {
                            "matches": sig.matches.len() as i64,
                            "categories": categories,
                            "severity": severity,
                        },
                    }),
                    None,
                )?;
                (
                    euid("Action", "PreToolUse")?,
                    euid("Tool", &tc.tool)?,
                    context,
                )
            }
            TrajectoryEvent::Action(Action::ShellCommand(sc)) => {
                let working_dir = sc.working_dir.as_deref().unwrap_or("");
                let sig = sondera_signature::scan(&sc.command);
                let severity: i64 = sig.severity.into();
                let categories: Vec<&str> = sig.categories.iter().map(|s| s.as_str()).collect();
                let (label, policy) = self.classify(&sc.command).await;
                let label_id = euid("Label", &label.to_string())?;

                let parse = shell_parse::analyze_shell_command(&sc.command);

                let context_value = serde_json::json!({
                    "workspace": workspace_ctx,
                    "command": sc.command,
                    // Required `String` in the schema — a `None` working_dir must
                    // serialize as "" rather than null, or the request fails
                    // context validation before any policy runs.
                    "working_dir": working_dir,
                    "label": label_id.to_json_value()?,
                    "policy": policy,
                    "signature": {
                        "matches": sig.matches.len() as i64,
                        "categories": categories,
                        "severity": severity,
                    },
                    "file_signature": {
                        "matches": 0,
                        "categories": [],
                        "severity": 0,
                    },
                    "parse": parse.to_cedar_json(),
                });
                let context = Context::from_json_value(context_value, None)?;
                (euid("Action", "ShellCommand")?, trajectory_id, context)
            }
            TrajectoryEvent::Action(Action::WebFetch(wf)) => {
                // Scan url + prompt content for signatures.
                let content = format!("{}\n{}", wf.url, wf.prompt);
                let sig = sondera_signature::scan(&content);
                let severity: i64 = sig.severity.into();
                let categories: Vec<&str> = sig.categories.iter().map(|s| s.as_str()).collect();

                let (label, policy) = self.classify(&content).await;
                let label_id = euid("Label", &label.to_string())?;

                let url_parse = url_parse::parse_url(&wf.url);

                let context_value = serde_json::json!({
                    "workspace": workspace_ctx,
                    "url": wf.url,
                    "prompt": wf.prompt,
                    "label": label_id.to_json_value()?,
                    "policy": policy,
                    "signature": {
                        "matches": sig.matches.len() as i64,
                        "categories": categories,
                        "severity": severity,
                    },
                    "url_parse": url_parse.to_cedar_json(),
                });
                let context = Context::from_json_value(context_value, None)?;
                (euid("Action", "WebFetch")?, trajectory_id, context)
            }
            TrajectoryEvent::Action(Action::FileOperation(fo)) => {
                // Build scannable content: path + content + old_content if present.
                let mut scannable = fo.path.clone();
                if let Some(content) = &fo.content {
                    scannable.push('\n');
                    scannable.push_str(content);
                }
                if let Some(old_content) = &fo.old_content {
                    scannable.push('\n');
                    scannable.push_str(old_content);
                }

                // Scan for YARA signatures.
                let sig = sondera_signature::scan(&scannable);
                let severity: i64 = sig.severity.into();
                let categories: Vec<&str> = sig.categories.iter().map(|s| s.as_str()).collect();

                let (label, policy) = self.classify(&scannable).await;
                let label_id = euid("Label", &label.to_string())?;

                // Create/update File entity with label.
                let file_id = euid("File", &fo.path)?;
                let file_entity = EntityBuilder::new(file_id.clone())
                    .entity_ref("label", "Label", &label.to_string())?
                    .build()?;
                self.store.upsert(&file_entity).await?;

                // Raise the trajectory label from the file label.
                self.mark_trajectory_label(&trajectory_uid, label).await?;

                let context_value = serde_json::json!({
                    "workspace": workspace_ctx,
                    "path": fo.path,
                    "path_normalized": path_normalize::normalize_path_value(&fo.path),
                    "operation": fo.operation.to_string(),
                    "label": label_id.to_json_value()?,
                    "policy": policy,
                    "signature": {
                        "matches": sig.matches.len() as i64,
                        "categories": categories,
                        "severity": severity,
                    }
                });
                let context = Context::from_json_value(context_value, None)?;
                let action = euid("Action", format!("File{}", fo.operation).as_str())?;
                (action, file_id, context)
            }
            TrajectoryEvent::Observation(Observation::ShellCommandOutput(sco)) => {
                // Scan stdout and stderr for signatures.
                let content = format!("{}\n{}", sco.stdout, sco.stderr);
                let sig = sondera_signature::scan(&content);
                let severity: i64 = sig.severity.into();
                let categories: Vec<&str> = sig.categories.iter().map(|s| s.as_str()).collect();

                let (label, policy) = self.classify(&content).await;
                let label_id = euid("Label", &label.to_string())?;
                self.mark_trajectory_label(&trajectory_uid, label).await?;

                let context_value = serde_json::json!({
                    "workspace": workspace_ctx,
                    "command": "",
                    "working_dir": "",
                    "exit_code": sco.exit_code as i64,
                    "stdout": sco.stdout,
                    "stderr": sco.stderr,
                    "label": label_id.to_json_value()?,
                    "policy": policy,
                    "signature": {
                        "matches": sig.matches.len() as i64,
                        "categories": categories,
                        "severity": severity,
                    }
                });
                let context = Context::from_json_value(context_value, None)?;
                (
                    euid("Action", "ShellCommandOutput")?,
                    trajectory_id,
                    context,
                )
            }
            TrajectoryEvent::Observation(Observation::WebFetchOutput(wfo)) => {
                // Scan result content for signatures.
                let sig = sondera_signature::scan(&wfo.result);
                let severity: i64 = sig.severity.into();
                let categories: Vec<&str> = sig.categories.iter().map(|s| s.as_str()).collect();

                let (label, policy) = self.classify(&wfo.result).await;
                let label_id = euid("Label", &label.to_string())?;
                self.mark_trajectory_label(&trajectory_uid, label).await?;

                let context_value = serde_json::json!({
                    "workspace": workspace_ctx,
                    "url": wfo.url,
                    "code": wfo.code as i64,
                    "result": wfo.result,
                    "label": label_id.to_json_value()?,
                    "policy": policy,
                    "signature": {
                        "matches": sig.matches.len() as i64,
                        "categories": categories,
                        "severity": severity,
                    }
                });
                let context = Context::from_json_value(context_value, None)?;
                (euid("Action", "WebFetchOutput")?, trajectory_id, context)
            }
            TrajectoryEvent::Observation(Observation::FileOperationResult(fo)) => {
                let path = fo.path.as_deref().unwrap_or("");

                // Scan result content for signatures.
                let content = fo.content.as_deref().unwrap_or("");
                let sig = sondera_signature::scan(content);
                let severity: i64 = sig.severity.into();
                let categories: Vec<&str> = sig.categories.iter().map(|s| s.as_str()).collect();

                let (label, policy) = self.classify(content).await;
                let label_id = euid("Label", &label.to_string())?;

                // Raise the trajectory label from the file content label.
                self.mark_trajectory_label(&trajectory_uid, label).await?;

                // Update File entity label if we have a path.
                if !path.is_empty() {
                    let file_entity = EntityBuilder::new(euid("File", path)?)
                        .entity_ref("label", "Label", &label.to_string())?
                        .build()?;
                    self.store.upsert(&file_entity).await?;
                }

                let context_value = serde_json::json!({
                    "workspace": workspace_ctx,
                    "path": path,
                    "path_normalized": path_normalize::normalize_path_value(path),
                    "content": content,
                    "label": label_id.to_json_value()?,
                    "policy": policy,
                    "signature": {
                        "matches": sig.matches.len() as i64,
                        "categories": categories,
                        "severity": severity,
                    }
                });
                let context = Context::from_json_value(context_value, None)?;
                (
                    euid("Action", "FileOperationResult")?,
                    trajectory_id,
                    context,
                )
            }
            TrajectoryEvent::Observation(Observation::ToolOutput(to)) => {
                // Scan tool output for signatures.
                let content = to
                    .output
                    .as_str()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| serde_json::to_string(&to.output).unwrap_or_default());
                let sig = sondera_signature::scan(&content);
                let severity: i64 = sig.severity.into();
                let categories: Vec<&str> = sig.categories.iter().map(|s| s.as_str()).collect();

                let (label, policy) = self.classify(&content).await;
                let label_id = euid("Label", &label.to_string())?;
                self.mark_trajectory_label(&trajectory_uid, label).await?;

                let context_value = serde_json::json!({
                    "workspace": workspace_ctx,
                    "content": content,
                    "label": label_id.to_json_value()?,
                    "policy": policy,
                    "signature": {
                        "matches": sig.matches.len() as i64,
                        "categories": categories,
                        "severity": severity,
                    }
                });
                let context = Context::from_json_value(context_value, None)?;
                (euid("Action", "ToolOutput")?, trajectory_id, context)
            }
            _ => {
                anyhow::bail!(
                    "Unsupported event type for Cedar authorization: {:?}",
                    event.event
                );
            }
        };
        let request = Request::new(
            principal_id,
            action_id,
            resource_id,
            context,
            Some(&self.schema),
        )?;
        Ok(request)
    }

    /// Map a Cedar response to an Adjudicated result.
    pub(super) fn response_to_adjudicated(&self, response: &cedar_policy::Response) -> Adjudicated {
        adjudicated_from_response(response, &self.policy_set)
    }
}

fn adjudicated_from_response(
    response: &cedar_policy::Response,
    policy_set: &cedar_policy::PolicySet,
) -> Adjudicated {
    let mut metadata = Vec::new();
    let mut has_hard_deny = false;
    let mut has_escalate = false;

    for policy_id in response.diagnostics().reason() {
        let mut entry = PolicyMetadata::new().with_id(policy_id.to_string());
        let mut is_escalate = false;
        let mut escalate_arg = None;

        if let Some(policy) = policy_set.policy(policy_id) {
            for (key, value) in policy.annotations() {
                match key.to_string().as_str() {
                    "id" => {}
                    "description" => {
                        entry = entry.with_description(value.to_string());
                    }
                    "escalate" => {
                        is_escalate = true;
                        let value = value.to_string();
                        if !value.is_empty() {
                            escalate_arg = Some(value);
                        }
                    }
                    other => {
                        entry = entry.with(other.to_string(), value.to_string());
                    }
                }
            }
        }

        if is_escalate {
            entry = entry.with_escalate(escalate_arg);
            has_escalate = true;
        } else if response.decision() == cedar_policy::Decision::Deny {
            has_hard_deny = true;
        }
        metadata.push(entry);
    }

    let decision = match response.decision() {
        cedar_policy::Decision::Allow => Decision::Allow,
        cedar_policy::Decision::Deny if has_escalate && !has_hard_deny => Decision::Escalate,
        cedar_policy::Decision::Deny => Decision::Deny,
    };
    let errors: Vec<String> = response
        .diagnostics()
        .errors()
        .map(ToString::to_string)
        .collect();
    let (decision, reason) = if errors.is_empty() {
        (decision, None)
    } else {
        (Decision::Deny, Some(errors.join("; ")))
    };

    let mut adjudicated = Adjudicated::new(decision);
    adjudicated.reason = reason;
    adjudicated.metadata = metadata;
    adjudicated
}

#[cfg(test)]
mod tests {
    use super::{
        BTreeSet, PolicyClassification, PolicyContext, adjudicated_from_response, classify_policy,
        workspace_context,
    };
    use cedar_policy::{Authorizer, Context, Entities, PolicySet, Request};
    use sondera_policy::PolicyViolation;
    use sondera_types::{Action, Agent, Decision, Event, ShellCommand, TrajectoryEvent};

    fn adjudicate(policy: &str) -> sondera_types::Adjudicated {
        let policies: PolicySet = policy.parse().expect("test policy parses");
        let request = Request::new(
            r#"Agent::"a""#.parse().unwrap(),
            r#"Action::"x""#.parse().unwrap(),
            r#"Resource::"r""#.parse().unwrap(),
            Context::empty(),
            None,
        )
        .expect("request builds");
        let response = Authorizer::new().is_authorized(&request, &policies, &Entities::empty());
        adjudicated_from_response(&response, &policies)
    }

    #[test]
    fn shell_working_dir_populates_workspace_cwd() {
        let event = Event::new(
            Agent {
                id: "agent".to_string(),
                provider: "test".to_string(),
                platform: String::new(),
            },
            "trajectory",
            TrajectoryEvent::Action(Action::ShellCommand(
                ShellCommand::new("pwd").with_cwd("/workspace/project"),
            )),
        );

        assert_eq!(workspace_context(&event).cwd, "/workspace/project");
    }

    #[test]
    fn escalate_annotation_maps_an_escalation_only_forbid() {
        let result = adjudicate(
            r#"@id("ask") @description("ask first") @escalate("owner approval")
               forbid (principal, action, resource);"#,
        );

        assert_eq!(result.decision, Decision::Escalate);
        assert!(result.metadata[0].escalate);
        assert_eq!(
            result.metadata[0].escalate_arg.as_deref(),
            Some("owner approval")
        );
    }

    #[test]
    fn hard_deny_outranks_escalation() {
        let result = adjudicate(
            r#"@id("ask") @description("ask first") @escalate("owner approval")
               forbid (principal, action, resource);
               @id("block") @description("always block")
               forbid (principal, action, resource);"#,
        );

        assert_eq!(result.decision, Decision::Deny);
    }

    /// With no classifier configured, adjudication still has to produce a
    /// schema-valid `PolicyContext` — and it has to be the value that makes a
    /// violation-gated forbid *not* fire, never a synthesized violation.
    #[tokio::test]
    async fn policy_context_fails_open_without_a_classifier() {
        let context = classify_policy(None, "rm -rf /").await;

        assert_eq!(context, PolicyContext::unjudged());
        assert_eq!(
            serde_json::to_value(&context).expect("context serializes"),
            serde_json::json!({ "compliant": true, "violations": [] })
        );
    }

    /// The context carries category *codes*, because that is the closed
    /// vocabulary policies match on and the MCP server serves. Emitting the
    /// human-readable names instead typechecks, validates, and leaves every
    /// violation-gated policy dead.
    #[test]
    fn policy_context_carries_codes_not_category_names() {
        let classification = PolicyClassification {
            compliant: false,
            violations: vec![PolicyViolation {
                category: "Injection".to_string(),
                rule: "SC2".to_string(),
                description: "Unsanitized input in a query.".to_string(),
            }],
        };

        let context = PolicyContext::from(classification);

        assert!(!context.compliant);
        assert_eq!(context.violations, BTreeSet::from(["SC2".to_string()]));
    }
}
