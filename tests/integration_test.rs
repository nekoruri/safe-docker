use std::io::Write;
use std::process::{Command, Stdio};

fn run_hook(input_json: &str) -> (String, i32) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_safe-docker"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn safe-docker");

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(input_json.as_bytes())
        .unwrap();

    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let exit_code = output.status.code().unwrap_or(-1);
    (stdout, exit_code)
}

fn make_bash_input(command: &str) -> String {
    serde_json::json!({
        "session_id": "test-session",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": command,
            "description": "test"
        },
        "cwd": "/tmp"
    })
    .to_string()
}

fn home_dir() -> String {
    dirs::home_dir()
        .unwrap()
        .to_string_lossy()
        .to_string()
}

// --- 非 docker コマンド: allow (exit 0, no output) ---

#[test]
fn test_non_docker_command() {
    let (stdout, exit_code) = run_hook(&make_bash_input("ls -la /tmp"));
    assert_eq!(exit_code, 0);
    assert!(stdout.trim().is_empty(), "Expected empty stdout for non-docker command");
}

#[test]
fn test_non_bash_tool() {
    let input = serde_json::json!({
        "session_id": "test-session",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {
            "file_path": "/etc/passwd"
        }
    })
    .to_string();

    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert!(stdout.trim().is_empty());
}

#[test]
fn test_invalid_json() {
    let (stdout, exit_code) = run_hook("not json at all");
    assert_eq!(exit_code, 0);
    // fail-safe: 不正な JSON は deny
    let output: serde_json::Value = serde_json::from_str(stdout.trim())
        .expect("Expected JSON output for invalid input (fail-safe)");
    assert_eq!(
        output["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny"),
        "Invalid JSON should be denied (fail-safe)"
    );
}

// --- docker run: mount outside $HOME → deny ---

#[test]
fn test_deny_mount_etc() {
    let (stdout, exit_code) = run_hook(&make_bash_input("docker run -v /etc:/data ubuntu"));
    assert_eq!(exit_code, 0);
    let output: serde_json::Value = serde_json::from_str(stdout.trim()).expect("Expected JSON output");
    assert_eq!(
        output["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny")
    );
    assert!(output["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap()
        .contains("outside $HOME"));
}

#[test]
fn test_deny_mount_root() {
    let (stdout, _) = run_hook(&make_bash_input("docker run -v /:/host ubuntu"));
    let output: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        output["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny")
    );
}

// --- docker run: mount inside $HOME → allow ---

#[test]
fn test_allow_mount_home() {
    let cmd = format!("docker run -v {}/projects:/app ubuntu", home_dir());
    let (stdout, exit_code) = run_hook(&make_bash_input(&cmd));
    assert_eq!(exit_code, 0);
    assert!(stdout.trim().is_empty(), "Expected empty stdout (allow) for $HOME mount");
}

#[test]
fn test_allow_tilde_mount() {
    let (stdout, exit_code) = run_hook(&make_bash_input("docker run -v ~/projects:/app ubuntu"));
    assert_eq!(exit_code, 0);
    assert!(stdout.trim().is_empty());
}

// --- docker run: sensitive path → ask ---

#[test]
fn test_ask_ssh_mount() {
    let cmd = format!("docker run -v {}/.ssh:/keys ubuntu", home_dir());
    let (stdout, exit_code) = run_hook(&make_bash_input(&cmd));
    assert_eq!(exit_code, 0);
    let output: serde_json::Value = serde_json::from_str(stdout.trim()).expect("Expected JSON output");
    assert_eq!(
        output["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("ask")
    );
}

// --- docker run: --privileged → deny ---

#[test]
fn test_deny_privileged() {
    let (stdout, exit_code) = run_hook(&make_bash_input("docker run --privileged ubuntu"));
    assert_eq!(exit_code, 0);
    let output: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        output["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny")
    );
    assert!(output["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap()
        .contains("privileged"));
}

// --- docker run: --cap-add SYS_ADMIN → deny ---

#[test]
fn test_deny_cap_add() {
    let (stdout, _) = run_hook(&make_bash_input("docker run --cap-add SYS_ADMIN ubuntu"));
    let output: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        output["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny")
    );
}

// --- docker run: --device → deny ---

#[test]
fn test_deny_device() {
    let (stdout, _) = run_hook(&make_bash_input("docker run --device /dev/sda ubuntu"));
    let output: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        output["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny")
    );
}

// --- docker run: --mount type=bind → deny for outside $HOME ---

#[test]
fn test_deny_mount_type_bind() {
    let (stdout, _) = run_hook(&make_bash_input(
        "docker run --mount type=bind,source=/etc,target=/data ubuntu",
    ));
    let output: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        output["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny")
    );
}

// --- docker ps: no volumes → allow ---

#[test]
fn test_allow_docker_ps() {
    let (stdout, exit_code) = run_hook(&make_bash_input("docker ps"));
    assert_eq!(exit_code, 0);
    assert!(stdout.trim().is_empty());
}

// --- chained command: deny if any docker segment is bad ---

#[test]
fn test_deny_chained_command() {
    let (stdout, _) = run_hook(&make_bash_input("cd /tmp && docker run -v /etc:/data ubuntu"));
    let output: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        output["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny")
    );
}

// --- piped command ---

#[test]
fn test_deny_piped_command() {
    let (stdout, _) = run_hook(&make_bash_input("echo test | docker run -v /etc:/data ubuntu"));
    let output: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        output["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny")
    );
}

// --- docker build: no mounts → allow ---

#[test]
fn test_allow_docker_build() {
    let (stdout, exit_code) = run_hook(&make_bash_input("docker build -t myapp ."));
    assert_eq!(exit_code, 0);
    assert!(stdout.trim().is_empty());
}

// --- docker run: no mounts → allow ---

#[test]
fn test_allow_docker_run_no_mounts() {
    let (stdout, exit_code) = run_hook(&make_bash_input("docker run ubuntu echo hello"));
    assert_eq!(exit_code, 0);
    assert!(stdout.trim().is_empty());
}

// --- docker socket mount → deny ---

#[test]
fn test_deny_docker_socket() {
    let (stdout, _) = run_hook(&make_bash_input(
        "docker run -v /var/run/docker.sock:/var/run/docker.sock ubuntu",
    ));
    let output: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        output["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny")
    );
}

// --- multiple violations → deny with multiple reasons ---

#[test]
fn test_deny_multiple_violations() {
    let (stdout, _) = run_hook(&make_bash_input(
        "docker run --privileged -v /etc:/data ubuntu",
    ));
    let output: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        output["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny")
    );
    let reason = output["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .unwrap();
    assert!(reason.contains("Multiple issues") || reason.contains("privileged"));
}

// --- 統合テスト拡充 ---

#[test]
fn test_empty_command() {
    let (stdout, exit_code) = run_hook(&make_bash_input(""));
    assert_eq!(exit_code, 0);
    assert!(stdout.trim().is_empty(), "Empty command should allow");
}

#[test]
fn test_missing_tool_input_command() {
    let input = serde_json::json!({
        "session_id": "test-session",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "description": "test"
        }
    })
    .to_string();

    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert!(
        stdout.trim().is_empty(),
        "Missing command field should allow"
    );
}

#[test]
fn test_very_long_command() {
    // 256KB を超えるコマンド → input too large で fail-safe (deny)
    let long_cmd = "a".repeat(257 * 1024);
    let input = serde_json::json!({
        "session_id": "test-session",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": long_cmd,
            "description": "test"
        }
    })
    .to_string();

    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    // fail-safe: 入力が大きすぎる場合は deny
    let output: serde_json::Value = serde_json::from_str(stdout.trim())
        .expect("Expected JSON output for oversized input (fail-safe)");
    assert_eq!(
        output["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny"),
        "Very long input should be denied (fail-safe)"
    );
}

#[test]
fn test_multiple_docker_segments_mixed() {
    // 一つが deny、一つが allow → deny 優先
    let cmd = format!(
        "docker run -v {}/projects:/app ubuntu && docker run -v /etc:/data ubuntu",
        home_dir()
    );
    let (stdout, _) = run_hook(&make_bash_input(&cmd));
    let output: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        output["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny"),
        "Mixed allow+deny segments should result in deny"
    );
}

#[test]
fn test_deny_compose_up_no_file() {
    let (stdout, exit_code) =
        run_hook(&make_bash_input("docker compose up"));
    assert_eq!(exit_code, 0);
    // /tmp に compose ファイルがない → deny
    let output: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        output["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny"),
        "compose up without compose file should deny"
    );
}

#[test]
fn test_deny_sudo_docker_outside_home() {
    let (stdout, _) = run_hook(&make_bash_input(
        "sudo docker run -v /etc:/data ubuntu",
    ));
    let output: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        output["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny")
    );
}

#[test]
fn test_deny_docker_host_env() {
    let (stdout, _) = run_hook(&make_bash_input(
        "DOCKER_HOST=tcp://evil:2375 docker run -v /etc:/data ubuntu",
    ));
    let output: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        output["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny")
    );
}

#[test]
fn test_deny_eval_docker_integration() {
    let (stdout, _) = run_hook(&make_bash_input(
        r#"eval "docker run -v /etc:/data ubuntu""#,
    ));
    let output: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        output["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny"),
        "eval docker should deny"
    );
}

#[test]
fn test_deny_bash_c_docker_integration() {
    let (stdout, _) = run_hook(&make_bash_input(
        r#"bash -c "docker run -v /etc:/data ubuntu""#,
    ));
    let output: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        output["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny"),
        "bash -c docker should deny"
    );
}

#[test]
fn test_deny_network_host_integration() {
    let (stdout, _) = run_hook(&make_bash_input("docker run --network=host ubuntu"));
    let output: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        output["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny")
    );
}

#[test]
fn test_deny_pid_host_integration() {
    let (stdout, _) = run_hook(&make_bash_input("docker run --pid=host ubuntu"));
    let output: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(
        output["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny")
    );
}

#[test]
fn test_allow_docker_compose_exec() {
    // compose exec は compose ファイルを解析しない
    let (stdout, exit_code) =
        run_hook(&make_bash_input("docker compose exec web bash"));
    assert_eq!(exit_code, 0);
    assert!(
        stdout.trim().is_empty(),
        "compose exec should allow (no file analysis)"
    );
}
