use super::CedarPolicyHarness;
use super::entity::{Trajectory, euid};
use crate::{
    Action, Adjudicated, Annotation, Decision, EntityBuilder, Event, Observation, TrajectoryEvent,
};
use anyhow::Result;
use cedar_policy::{Context, Request};
use serde::Serialize;
use sondera_information_flow_control::Label;
use std::path::Path;
use tracing::debug;

#[derive(Debug, Clone, Serialize, PartialEq)]
struct WorkspaceContext {
    cwd: String,
    permission_mode: String,
    transcript_path: String,
}

fn workspace_context(event: &Event) -> WorkspaceContext {
    let raw = event.raw.as_ref();
    let field = |key| {
        raw.and_then(|r| r.get(key))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    WorkspaceContext {
        cwd: field("cwd"),
        permission_mode: field("permission_mode"),
        transcript_path: field("transcript_path"),
    }
}

/// Parse file paths from a shell command string using `shlex`.
fn parse_file_paths(command: &str) -> Vec<String> {
    let mut paths = Vec::new();

    // Robustly tokenize the command string.
    // This safely handles quotes, escaped characters, and whitespace.
    // It returns `None` if the quotes are unbalanced/invalid.
    let tokens = match shlex::split(command) {
        Some(t) => t,
        None => return vec![],
    };

    let shell_operators = ["|", ">", ">>", "<", "&&", "||", ";", "2>&1", "&"];

    // Skip the first token (the command binary itself).
    for mut token in tokens.into_iter().skip(1) {
        // Skip flags and shell operators.
        if token.starts_with('-') || shell_operators.contains(&token.as_str()) {
            continue;
        }

        // Handle `key=value` formats (e.g., `--out=file.txt` or `OUT=file.txt`).
        if let Some((_, val)) = token.split_once('=') {
            token = val.to_string();
        }

        let path = Path::new(&token);

        let has_separator = token.contains('/') || token.contains('\\');
        let is_dot_dir = token == "." || token == "..";
        let has_valid_extension = path.extension().is_some_and(|ext| {
            let ext_str = ext.to_string_lossy();
            !ext_str.is_empty()
                && ext_str.len() <= 10
                && ext_str.chars().all(|c| c.is_alphanumeric())
        });

        if has_separator || has_valid_extension || is_dot_dir {
            paths.push(token);
        }
    }

    paths
}

impl CedarPolicyHarness {
    /// Build a Cedar authorization request from an Event.
    pub(super) async fn build_request(&self, event: &Event) -> Result<Request> {
        let workspace_ctx = workspace_context(event);
        let principal_id = euid("Agent", &event.actor.id)?;
        let trajectory_id = euid("Trajectory", &event.trajectory_id)?;
        let trajectory_entity = match self.entity_store.get(&trajectory_id)? {
            Some(entity) => entity,
            None => {
                debug!(
                    "Trajectory {:?} not found, creating new.",
                    &event.trajectory_id
                );
                let trajectory = Trajectory::new(&event.trajectory_id);
                self.entity_store
                    .upsert(&trajectory.clone().into_entity()?)?;
                trajectory.into_entity()?
            }
        };
        let mut trajectory = Trajectory::try_from(trajectory_entity)?;

        // Increment step count and persist for each adjudicated event.
        trajectory.step_count += 1;
        self.entity_store
            .upsert(&trajectory.clone().into_entity()?)?;

        let mut mark_trajectory_label = |label: Label| -> Result<()> {
            // Set the max sensitivity label on Trajectory.
            if label.level() > trajectory.label.level() {
                trajectory.label = label;
                debug!(
                    "Marking trajectory: {:?} with label: {:?}",
                    &trajectory.trajectory_id, label
                );
                self.entity_store
                    .upsert(&trajectory.clone().into_entity()?)?;
            }
            Ok(())
        };

        let (action_id, resource_id, context) = match &event.event {
            TrajectoryEvent::Observation(Observation::Prompt(prompt)) => {
                let message_id = euid("Message", &event.event_id)?;

                // Build signature context from prompt content.
                let sig = sondera_signature::scan(&prompt.content);
                let severity: i64 = sig.severity.into();
                let categories: Vec<&str> = sig.categories.iter().map(|s| s.as_str()).collect();

                // Get the max sensitivity label of Message.
                let label = self.data_model.classify(&prompt.content).await?.max_label();
                let label_id = euid("Label", &label.to_string())?;

                // Build Message entity and add to store.
                let message = EntityBuilder::new(message_id)
                    .parent_uid(trajectory_id)
                    .string("content", &prompt.content)
                    .string("role", &prompt.role.to_string().to_lowercase())
                    .build()?;
                self.entity_store.upsert(&message)?;

                mark_trajectory_label(label)?;

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
            TrajectoryEvent::Action(Action::ToolCall(tc)) => (
                euid("Action", "PreToolUse")?,
                euid("Tool", &tc.tool)?,
                Context::empty(),
            ),
            TrajectoryEvent::Action(Action::ShellCommand(sc)) => {
                // Parse file paths from the command and load their content.
                let file_paths = parse_file_paths(&sc.command);
                let working_dir = sc.working_dir.as_deref().unwrap_or("");
                let mut file_contents = String::new();
                for path_str in &file_paths {
                    let path = std::path::Path::new(path_str);
                    let resolved = if path.is_relative() && !working_dir.is_empty() {
                        std::path::PathBuf::from(working_dir).join(path)
                    } else {
                        path.to_path_buf()
                    };
                    if let Ok(content) = std::fs::read_to_string(&resolved) {
                        file_contents.push('\n');
                        file_contents.push_str(&content);
                    }
                }

                // Combine command text with resolved file contents for scanning.
                let scannable = if file_contents.is_empty() {
                    sc.command.clone()
                } else {
                    format!("{}{}", sc.command, file_contents)
                };

                // Build signature context from combined content.
                let sig = sondera_signature::scan(&scannable);
                let severity: i64 = sig.severity.into();
                let categories: Vec<&str> = sig.categories.iter().map(|s| s.as_str()).collect();

                // Classify the sensitivity of combined content.
                let label = self.data_model.classify(&scannable).await?.max_label();
                let label_id = euid("Label", &label.to_string())?;

                let policy_classification = self.policy_model.evaluate_content(&scannable).await?;

                let context_value = serde_json::json!({
                    "workspace": workspace_ctx,
                    "command": sc.command,
                    "working_dir": sc.working_dir,
                    "label": label_id.to_json_value()?,
                    "policy": {
                        "compliant": policy_classification.compliant,
                        "violations": policy_classification.categories(),
                    },
                    "signature": {
                        "matches": sig.matches.len() as i64,
                        "categories": categories,
                        "severity": severity,
                    }
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

                // Classify the sensitivity of content.
                let label = self.data_model.classify(&content).await?.max_label();
                let label_id = euid("Label", &label.to_string())?;

                // Evaluate content against policy model.
                let policy_classification = self.policy_model.evaluate_content(&content).await?;

                let context_value = serde_json::json!({
                    "workspace": workspace_ctx,
                    "url": wf.url,
                    "prompt": wf.prompt,
                    "label": label_id.to_json_value()?,
                    "policy": {
                        "compliant": policy_classification.compliant,
                        "violations": policy_classification.categories(),
                    },
                    "signature": {
                        "matches": sig.matches.len() as i64,
                        "categories": categories,
                        "severity": severity,
                    }
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

                // Classify data sensitivity.
                let label = self.data_model.classify(&scannable).await?.max_label();
                let label_id = euid("Label", &label.to_string())?;

                // Evaluate against policy model.
                let policy_classification = self.policy_model.evaluate_content(&scannable).await?;

                // Create/update File entity with label.
                let file_id = euid("File", &fo.path)?;
                let file_entity = EntityBuilder::new(file_id.clone())
                    .entity_ref("label", "Label", &label.to_string())?
                    .build()?;
                self.entity_store.upsert(&file_entity)?;

                // Taint trajectory with file label.
                mark_trajectory_label(label)?;

                let context_value = serde_json::json!({
                    "workspace": workspace_ctx,
                    "path": fo.path,
                    "operation": fo.operation.to_string(),
                    "label": label_id.to_json_value()?,
                    "policy": {
                        "compliant": policy_classification.compliant,
                        "violations": policy_classification.categories(),
                    },
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

                // Classify the sensitivity of output content.
                let label = self.data_model.classify(&content).await?.max_label();
                let label_id = euid("Label", &label.to_string())?;
                mark_trajectory_label(label)?;

                // Evaluate output content against policy model.
                let policy_classification = self.policy_model.evaluate_content(&content).await?;

                let context_value = serde_json::json!({
                    "workspace": workspace_ctx,
                    "command": "",
                    "working_dir": "",
                    "exit_code": sco.exit_code as i64,
                    "stdout": sco.stdout,
                    "stderr": sco.stderr,
                    "label": label_id.to_json_value()?,
                    "policy": {
                        "compliant": policy_classification.compliant,
                        "violations": policy_classification.categories(),
                    },
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

                // Classify the sensitivity of result content.
                let label = self.data_model.classify(&wfo.result).await?.max_label();
                let label_id = euid("Label", &label.to_string())?;
                mark_trajectory_label(label)?;

                // Evaluate result content against policy model.
                let policy_classification = self.policy_model.evaluate_content(&wfo.result).await?;

                let context_value = serde_json::json!({
                    "workspace": workspace_ctx,
                    "url": wfo.url,
                    "code": wfo.code as i64,
                    "result": wfo.result,
                    "label": label_id.to_json_value()?,
                    "policy": {
                        "compliant": policy_classification.compliant,
                        "violations": policy_classification.categories(),
                    },
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
                // Extract path from raw event data.
                let raw = event.raw.as_ref();
                let path = raw
                    .and_then(|r| r.get("tool_input"))
                    .and_then(|ti| ti.get("file_path"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                // Scan result content for signatures.
                let content = fo.content.as_deref().unwrap_or("");
                let sig = sondera_signature::scan(content);
                let severity: i64 = sig.severity.into();
                let categories: Vec<&str> = sig.categories.iter().map(|s| s.as_str()).collect();

                // Classify sensitivity of result content.
                let label = self.data_model.classify(content).await?.max_label();
                let label_id = euid("Label", &label.to_string())?;

                // Taint trajectory with file content label.
                mark_trajectory_label(label)?;

                // Evaluate result content against policy model.
                let policy_classification = self.policy_model.evaluate_content(content).await?;

                // Update File entity label if we have a path.
                if !path.is_empty() {
                    let file_entity = EntityBuilder::new(euid("File", path)?)
                        .entity_ref("label", "Label", &label.to_string())?
                        .build()?;
                    self.entity_store.upsert(&file_entity)?;
                }

                let context_value = serde_json::json!({
                    "workspace": workspace_ctx,
                    "path": path,
                    "content": content,
                    "label": label_id.to_json_value()?,
                    "policy": {
                        "compliant": policy_classification.compliant,
                        "violations": policy_classification.categories(),
                    },
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

                // Classify the sensitivity of output content.
                let label = self.data_model.classify(&content).await?.max_label();
                let label_id = euid("Label", &label.to_string())?;
                mark_trajectory_label(label)?;

                // Evaluate output content against policy model.
                let policy_classification = self.policy_model.evaluate_content(&content).await?;

                let context_value = serde_json::json!({
                    "workspace": workspace_ctx,
                    "content": content,
                    "label": label_id.to_json_value()?,
                    "policy": {
                        "compliant": policy_classification.compliant,
                        "violations": policy_classification.categories(),
                    },
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
        let decision = match response.decision() {
            cedar_policy::Decision::Allow => Decision::Allow,
            cedar_policy::Decision::Deny => Decision::Deny,
        };

        let annotations: Vec<Annotation> = response
            .diagnostics()
            .reason()
            .map(|policy_id| {
                let mut annotation = Annotation::new().with_id(policy_id.to_string());
                if let Some(policy) = self.policy_set.policy(policy_id) {
                    for (key, value) in policy.annotations() {
                        match key.to_string().as_str() {
                            "id" => {} // already captured as policy_id
                            "description" => {
                                annotation = annotation.with_description(value.to_string());
                            }
                            other => {
                                annotation = annotation.with(other.to_string(), value.to_string());
                            }
                        }
                    }
                }
                annotation
            })
            .collect();

        let errors: Vec<String> = response
            .diagnostics()
            .errors()
            .map(|e| e.to_string())
            .collect();

        let reason = if errors.is_empty() {
            None
        } else {
            Some(errors.join("; "))
        };

        Adjudicated {
            decision,
            reason,
            annotations,
        }
    }
}
