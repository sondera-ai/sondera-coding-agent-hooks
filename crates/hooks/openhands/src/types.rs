//! Type definitions for OpenHands SDK hook events.
//!
//! The SDK's canonical input shape is `HookEvent` with fields like
//! `event_type`, `message`, and `working_dir`. The structs intentionally accept
//! Claude/Codex-style aliases where harmless so the adapter remains compatible
//! with older OpenHands builds and docs examples.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sondera_hooks::error::{HookError, Result};
use std::collections::HashMap;

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct CommonInput {
    #[serde(default, alias = "hook_event_name", alias = "eventType")]
    pub event_type: String,
    #[serde(default)]
    pub session_id: String,
    #[serde(default, alias = "cwd", alias = "workspace_root")]
    pub working_dir: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub metadata: HashMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionStartEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PreToolUseEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(default)]
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: Value,
    #[serde(
        default,
        alias = "tool_use_id",
        alias = "call_id",
        alias = "toolCallId"
    )]
    pub tool_call_id: String,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PostToolUseEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(default)]
    pub tool_name: String,
    #[serde(default)]
    pub tool_input: Value,
    #[serde(default)]
    pub tool_response: Value,
    #[serde(
        default,
        alias = "tool_use_id",
        alias = "call_id",
        alias = "toolCallId"
    )]
    pub tool_call_id: String,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserPromptSubmitEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(default, alias = "prompt", alias = "user_message")]
    pub message: String,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StopEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default, alias = "last_assistant_message")]
    pub message: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SessionEndEvent {
    #[serde(flatten)]
    pub common: CommonInput,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl CommonInput {
    pub fn trajectory_key(&self) -> String {
        if !self.session_id.trim().is_empty() {
            self.session_id.clone()
        } else if !self.working_dir.trim().is_empty() {
            self.working_dir.clone()
        } else {
            "openhands-session".to_string()
        }
    }

    pub fn working_dir_or_current(&self) -> String {
        if self.working_dir.trim().is_empty() {
            std::env::current_dir()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default()
        } else {
            self.working_dir.clone()
        }
    }

    pub fn metadata_string(&self, key: &str) -> Option<String> {
        self.metadata
            .get(key)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    }
}

impl PreToolUseEvent {
    pub fn validate(&self) -> Result<()> {
        if self.tool_name.trim().is_empty() {
            return Err(HookError::message("tool_name cannot be empty"));
        }
        Ok(())
    }

    pub fn call_id(&self) -> String {
        call_id(&self.tool_call_id, &self.common, &self.tool_name)
    }
}

impl PostToolUseEvent {
    pub fn validate(&self) -> Result<()> {
        if self.tool_name.trim().is_empty() {
            return Err(HookError::message("tool_name cannot be empty"));
        }
        Ok(())
    }

    pub fn call_id(&self) -> String {
        call_id(&self.tool_call_id, &self.common, &self.tool_name)
    }
}

impl SessionStartEvent {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl UserPromptSubmitEvent {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }
}

impl StopEvent {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }

    pub fn stop_reason(&self) -> Option<String> {
        self.reason
            .clone()
            .or_else(|| self.common.metadata_string("reason"))
    }
}

impl SessionEndEvent {
    pub fn validate(&self) -> Result<()> {
        Ok(())
    }

    pub fn end_reason(&self) -> Option<String> {
        self.reason
            .clone()
            .or_else(|| self.common.metadata_string("reason"))
    }
}

fn call_id(explicit: &str, common: &CommonInput, tool_name: &str) -> String {
    if !explicit.trim().is_empty() {
        return explicit.to_string();
    }
    for key in ["tool_call_id", "tool_use_id", "call_id", "id"] {
        if let Some(value) = common.metadata_string(key) {
            return value;
        }
    }
    format!("{}:{}", common.trajectory_key(), tool_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn event_round_trips_and_preserves_extra_fields() {
        let cases = [
            json!({"event_type":"SessionStart","session_id":"s1","working_dir":"/tmp/p","metadata":{"model":"x"},"future":1}),
            json!({"event_type":"PreToolUse","session_id":"s1","working_dir":"/tmp/p","tool_name":"terminal","tool_input":{"command":"ls"},"future":1}),
            json!({"event_type":"PostToolUse","session_id":"s1","working_dir":"/tmp/p","tool_name":"terminal","tool_input":{"command":"ls"},"tool_response":{"output":"ok"},"future":1}),
            json!({"event_type":"UserPromptSubmit","session_id":"s1","working_dir":"/tmp/p","message":"hello","future":1}),
            json!({"event_type":"Stop","session_id":"s1","working_dir":"/tmp/p","metadata":{"reason":"done"},"future":1}),
            json!({"event_type":"SessionEnd","session_id":"s1","working_dir":"/tmp/p","reason":"done","future":1}),
        ];

        let start: SessionStartEvent = serde_json::from_value(cases[0].clone()).unwrap();
        assert_eq!(start.extra.get("future"), Some(&json!(1)));
        assert_eq!(serde_json::to_value(&start).unwrap()["future"], json!(1));

        let pre: PreToolUseEvent = serde_json::from_value(cases[1].clone()).unwrap();
        assert_eq!(pre.extra.get("future"), Some(&json!(1)));
        assert_eq!(serde_json::to_value(&pre).unwrap()["future"], json!(1));

        let post: PostToolUseEvent = serde_json::from_value(cases[2].clone()).unwrap();
        assert_eq!(post.extra.get("future"), Some(&json!(1)));
        assert_eq!(serde_json::to_value(&post).unwrap()["future"], json!(1));

        let prompt: UserPromptSubmitEvent = serde_json::from_value(cases[3].clone()).unwrap();
        assert_eq!(prompt.extra.get("future"), Some(&json!(1)));
        assert_eq!(serde_json::to_value(&prompt).unwrap()["future"], json!(1));

        let stop: StopEvent = serde_json::from_value(cases[4].clone()).unwrap();
        assert_eq!(stop.stop_reason().as_deref(), Some("done"));
        assert_eq!(stop.extra.get("future"), Some(&json!(1)));
        assert_eq!(serde_json::to_value(&stop).unwrap()["future"], json!(1));

        let end: SessionEndEvent = serde_json::from_value(cases[5].clone()).unwrap();
        assert_eq!(end.end_reason().as_deref(), Some("done"));
        assert_eq!(end.extra.get("future"), Some(&json!(1)));
        assert_eq!(serde_json::to_value(&end).unwrap()["future"], json!(1));
    }

    #[test]
    fn user_prompt_accepts_aliases() {
        for (field, expected) in [("message", "a"), ("prompt", "b"), ("user_message", "c")] {
            let event: UserPromptSubmitEvent =
                serde_json::from_value(json!({field: expected})).unwrap();
            assert_eq!(event.message, expected);
        }
    }

    #[test]
    fn common_accepts_openhands_and_compat_field_names() {
        let event: SessionStartEvent = serde_json::from_value(json!({
            "hook_event_name":"SessionStart",
            "cwd":"/repo",
            "session_id":"s1"
        }))
        .unwrap();
        assert_eq!(event.common.event_type, "SessionStart");
        assert_eq!(event.common.working_dir, "/repo");
    }
}
