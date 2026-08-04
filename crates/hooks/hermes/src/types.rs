//! Type definitions for Hermes Agent shell-hook payloads.
//!
//! Hermes shell hooks send a stable top-level envelope and hook-specific fields.
//! The structs below keep that envelope permissive so the adapter survives
//! Hermes payload additions without losing raw evidence. Unknown top-level keys
//! are captured in `extra`; a nested `extra` object is also accepted for tests
//! and forward compatibility.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sondera_hooks::error::{HookError, Result};

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct HermesHookEvent {
    #[serde(default)]
    pub hook_event_name: String,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub tool_input: Option<Value>,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub cwd: String,
    #[serde(default, flatten)]
    pub extra: Map<String, Value>,
}

impl HermesHookEvent {
    pub fn validate_tool_event(&self) -> Result<()> {
        if self.tool_name().is_none() {
            return Err(HookError::message(
                "tool_name cannot be empty for Hermes tool hooks",
            ));
        }
        Ok(())
    }

    pub fn trajectory_key(&self) -> String {
        if !self.session_id.trim().is_empty() {
            self.session_id.clone()
        } else if !self.cwd.trim().is_empty() {
            self.cwd.clone()
        } else {
            "hermes-session".to_string()
        }
    }

    pub fn working_dir_or_current(&self) -> String {
        if self.cwd.trim().is_empty() {
            std::env::current_dir()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default()
        } else {
            self.cwd.clone()
        }
    }

    pub fn tool_name(&self) -> Option<&str> {
        self.tool_name
            .as_deref()
            .filter(|name| !name.trim().is_empty())
    }

    pub fn tool_input(&self) -> Value {
        self.tool_input.clone().unwrap_or(Value::Null)
    }

    pub fn call_id(&self) -> String {
        for key in ["tool_call_id", "tool_use_id", "call_id", "id"] {
            if let Some(value) = self.extra_string(key) {
                return value;
            }
        }
        // Hermes should provide a per-call ID. This fallback is stable across
        // action/observation hooks but is not unique for repeated calls to the
        // same tool in one session.
        let tool = self.tool_name().unwrap_or("event");
        format!("{}:{tool}", self.trajectory_key())
    }

    fn extra_value(&self, key: &str) -> Option<&Value> {
        self.extra.get(key).or_else(|| {
            self.extra
                .get("extra")
                .and_then(Value::as_object)
                .and_then(|nested| nested.get(key))
        })
    }

    pub fn extra_string(&self, key: &str) -> Option<String> {
        self.extra_value(key)
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
    }

    pub fn extra_i32(&self, key: &str) -> Option<i32> {
        self.extra_value(key)
            .and_then(Value::as_i64)
            .and_then(|n| i32::try_from(n).ok())
    }

    pub fn user_message(&self) -> Option<String> {
        self.extra_string("user_message")
            .or_else(|| self.extra_string("message"))
    }

    pub fn assistant_response(&self) -> Option<String> {
        self.extra_string("assistant_response")
            .or_else(|| self.extra_string("response_text"))
            .or_else(|| self.extra_string("response"))
    }

    pub fn tool_result(&self) -> Option<String> {
        self.extra_string("result")
            .or_else(|| self.extra_string("tool_result"))
            .or_else(|| self.extra_string("output"))
    }

    pub fn terminal_command(&self) -> String {
        self.extra_string("command")
            .or_else(|| command_from_value(&self.tool_input()))
            .unwrap_or_default()
    }

    pub fn terminal_output(&self) -> String {
        self.extra_string("output")
            .or_else(|| self.extra_string("stdout"))
            .or_else(|| self.tool_result())
            .unwrap_or_default()
    }

    pub fn terminal_stderr(&self) -> String {
        self.extra_string("stderr").unwrap_or_default()
    }

    pub fn terminal_exit_code(&self) -> i32 {
        self.extra_i32("exit_code").unwrap_or(0)
    }
}

pub fn command_from_value(input: &Value) -> Option<String> {
    if let Some(command) = input.as_str() {
        return Some(command.to_string());
    }
    for key in ["command", "cmd", "input"] {
        if let Some(command) = input.get(key).and_then(Value::as_str) {
            return Some(command.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_shell_hook_envelope_and_preserves_correlation_id() {
        let event: HermesHookEvent = serde_json::from_value(json!({
            "hook_event_name": "pre_tool_call",
            "tool_name": "terminal",
            "tool_input": {"command": "pwd"},
            "session_id": "sess-1",
            "cwd": "/tmp/project",
            "extra": {"tool_call_id": "call-1", "duration_ms": 7}
        }))
        .unwrap();

        assert_eq!(event.tool_name(), Some("terminal"));
        assert_eq!(event.call_id(), "call-1");
        assert_eq!(event.trajectory_key(), "sess-1");
        assert_eq!(event.terminal_command(), "pwd");
    }

    #[test]
    fn parses_flat_top_level_hermes_fields() {
        let event: HermesHookEvent = serde_json::from_value(json!({
            "hook_event_name": "post_tool_call",
            "tool_name": "terminal",
            "tool_input": {"command": "pwd"},
            "session_id": "sess-1",
            "cwd": "/tmp/project",
            "tool_call_id": "call-1",
            "output": "ok",
            "exit_code": 2
        }))
        .unwrap();

        assert_eq!(event.call_id(), "call-1");
        assert_eq!(event.tool_result(), Some("ok".to_string()));
        assert_eq!(event.terminal_exit_code(), 2);
    }

    #[test]
    fn fallback_call_id_is_stable_for_matching_action_observation() {
        let event: HermesHookEvent = serde_json::from_value(json!({
            "tool_name": "read_file",
            "session_id": "sess-1",
            "extra": {}
        }))
        .unwrap();

        assert_eq!(event.call_id(), "sess-1:read_file");
    }
}
