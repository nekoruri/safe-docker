use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write as _};

use crate::error::{Result, SafeDockerError};

const MAX_INPUT_BYTES: usize = 256 * 1024; // 256KB

// --- Input structures ---

#[derive(Debug, Deserialize)]
pub struct HookInput {
    #[serde(default)]
    pub session_id: Option<String>,

    #[serde(default)]
    pub hook_event_name: Option<String>,

    #[serde(default)]
    pub tool_name: Option<String>,

    #[serde(default)]
    pub tool_input: Option<ToolInput>,

    #[serde(default)]
    pub cwd: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ToolInput {
    #[serde(default)]
    pub command: Option<String>,

    #[serde(default)]
    pub description: Option<String>,
}

// --- Output structures ---

#[derive(Debug, Serialize)]
pub struct HookOutput {
    #[serde(rename = "hookSpecificOutput")]
    pub hook_specific_output: HookSpecificOutput,
}

#[derive(Debug, Serialize)]
pub struct HookSpecificOutput {
    #[serde(rename = "hookEventName")]
    pub hook_event_name: String,

    #[serde(rename = "permissionDecision")]
    pub permission_decision: String,

    #[serde(rename = "permissionDecisionReason")]
    pub permission_decision_reason: String,
}

// --- Decision types ---

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(String),
    Ask(String),
}

// --- Functions ---

/// stdin から hook 入力 JSON を読み取る
pub fn read_input() -> Result<HookInput> {
    let mut input = String::with_capacity(256);
    let stdin = io::stdin();
    let mut handle = stdin.lock().take(MAX_INPUT_BYTES as u64 + 1);
    handle.read_to_string(&mut input)?;

    if input.len() > MAX_INPUT_BYTES {
        return Err(SafeDockerError::InputTooLarge(input.len()));
    }

    let hook_input: HookInput = serde_json::from_str(&input)?;
    Ok(hook_input)
}

/// Bash ツール呼び出しからコマンド文字列を抽出する。
/// 非Bash or コマンドなしの場合は None を返す。
pub fn extract_command(input: &HookInput) -> Option<&str> {
    let tool_name = input.tool_name.as_deref()?;
    if !tool_name.eq_ignore_ascii_case("bash") {
        return None;
    }
    input
        .tool_input
        .as_ref()
        .and_then(|ti| ti.command.as_deref())
}

/// deny 判定結果を stdout に JSON 出力する
pub fn output_deny(reason: &str) {
    let output = HookOutput {
        hook_specific_output: HookSpecificOutput {
            hook_event_name: "PreToolUse".to_string(),
            permission_decision: "deny".to_string(),
            permission_decision_reason: reason.to_string(),
        },
    };
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    let _ = serde_json::to_writer(&mut handle, &output);
    let _ = writeln!(handle);
}

/// ask 判定結果を stdout に JSON 出力する
pub fn output_ask(reason: &str) {
    let output = HookOutput {
        hook_specific_output: HookSpecificOutput {
            hook_event_name: "PreToolUse".to_string(),
            permission_decision: "ask".to_string(),
            permission_decision_reason: reason.to_string(),
        },
    };
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    let _ = serde_json::to_writer(&mut handle, &output);
    let _ = writeln!(handle);
}

/// Decision に基づいて出力する。Allow の場合は何も出力しない。
pub fn output_decision(decision: &Decision) {
    match decision {
        Decision::Allow => {}
        Decision::Deny(reason) => output_deny(reason),
        Decision::Ask(reason) => output_ask(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_command_bash() {
        let input = HookInput {
            session_id: None,
            hook_event_name: Some("PreToolUse".to_string()),
            tool_name: Some("Bash".to_string()),
            tool_input: Some(ToolInput {
                command: Some("docker run ubuntu".to_string()),
                description: None,
            }),
            cwd: None,
        };
        assert_eq!(extract_command(&input), Some("docker run ubuntu"));
    }

    #[test]
    fn test_extract_command_non_bash() {
        let input = HookInput {
            session_id: None,
            hook_event_name: Some("PreToolUse".to_string()),
            tool_name: Some("Read".to_string()),
            tool_input: None,
            cwd: None,
        };
        assert_eq!(extract_command(&input), None);
    }

    #[test]
    fn test_extract_command_no_command() {
        let input = HookInput {
            session_id: None,
            hook_event_name: Some("PreToolUse".to_string()),
            tool_name: Some("Bash".to_string()),
            tool_input: Some(ToolInput {
                command: None,
                description: None,
            }),
            cwd: None,
        };
        assert_eq!(extract_command(&input), None);
    }

    #[test]
    fn test_deserialize_hook_input() {
        let json = r#"{
            "session_id": "abc123",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {
                "command": "docker run -v /etc:/data ubuntu",
                "description": "Run container"
            },
            "cwd": "/home/user/project"
        }"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.tool_name.as_deref(), Some("Bash"));
        assert_eq!(
            extract_command(&input),
            Some("docker run -v /etc:/data ubuntu")
        );
    }

    #[test]
    fn test_decision_deny_output() {
        // Just verify it doesn't panic
        let decision = Decision::Deny("test reason".to_string());
        output_decision(&decision);
    }
}
