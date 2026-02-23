/// セキュリティバイパスパターンの検出テスト。
/// シェル間接実行、パストラバーサル、セキュリティオプション回避等を検証する。
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

fn assert_deny(stdout: &str, msg: &str) {
    let output: serde_json::Value =
        serde_json::from_str(stdout.trim()).unwrap_or_else(|_| panic!("Expected JSON for: {}", msg));
    assert_eq!(
        output["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("deny"),
        "Expected deny for: {}",
        msg
    );
}

// --- シェル間接実行テスト ---

#[test]
fn test_deny_eval_docker() {
    let (stdout, exit_code) =
        run_hook(&make_bash_input(r#"eval "docker run -v /etc:/data ubuntu""#));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "eval docker run");
}

#[test]
fn test_deny_bash_c_docker() {
    let (stdout, exit_code) =
        run_hook(&make_bash_input(r#"bash -c "docker run -v /etc:/data ubuntu""#));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "bash -c docker run");
}

#[test]
fn test_deny_sh_c_docker_single_quote() {
    let (stdout, exit_code) =
        run_hook(&make_bash_input("sh -c 'docker run -v /etc:/data ubuntu'"));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "sh -c (single quote) docker run");
}

#[test]
fn test_deny_path_traversal_home() {
    let home = dirs::home_dir().unwrap().to_string_lossy().to_string();
    let cmd = format!("docker run -v {}/../../etc:/data ubuntu", home);
    let (stdout, exit_code) = run_hook(&make_bash_input(&cmd));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "path traversal $HOME/../../etc");
}

#[test]
fn test_deny_docker_socket_with_dot() {
    let (stdout, exit_code) = run_hook(&make_bash_input(
        "docker run -v /var/run/docker.sock/./:/sock ubuntu",
    ));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "docker.sock/./");
}

#[test]
fn test_deny_security_opt_seccomp_unconfined() {
    let (stdout, exit_code) = run_hook(&make_bash_input(
        "docker run --security-opt seccomp=unconfined ubuntu",
    ));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--security-opt seccomp=unconfined");
}

#[test]
fn test_deny_security_opt_apparmor_colon() {
    let (stdout, exit_code) = run_hook(&make_bash_input(
        "docker run --security-opt apparmor:unconfined ubuntu",
    ));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--security-opt apparmor:unconfined (colon)");
}

#[test]
fn test_deny_net_host_space() {
    let (stdout, exit_code) =
        run_hook(&make_bash_input("docker run --net host ubuntu"));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--net host (space-separated)");
}

#[test]
fn test_deny_subshell_with_docker() {
    // サブシェル内で分割後、docker コマンドが検出されるか
    let (stdout, exit_code) = run_hook(&make_bash_input(
        r#"echo ")" && docker run -v /etc:/data ubuntu"#,
    ));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "subshell bypass attempt with quoted )");
}

#[test]
fn test_deny_sudo_docker_mount() {
    let (stdout, exit_code) = run_hook(&make_bash_input(
        "sudo docker run -v /etc:/data ubuntu",
    ));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "sudo docker with outside-home mount");
}

#[test]
fn test_deny_docker_host_env_docker() {
    let (stdout, exit_code) = run_hook(&make_bash_input(
        "DOCKER_HOST=tcp://evil:2375 docker run -v /etc:/data ubuntu",
    ));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "DOCKER_HOST= docker with outside-home mount");
}

#[test]
fn test_deny_eval_with_sudo() {
    let (stdout, exit_code) = run_hook(&make_bash_input(
        r#"sudo eval "docker run -v /etc:/data ubuntu""#,
    ));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "sudo eval docker");
}

#[test]
fn test_deny_sudo_bash_c_docker() {
    let (stdout, exit_code) = run_hook(&make_bash_input(
        r#"sudo bash -c "docker run -v /etc:/data ubuntu""#,
    ));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "sudo bash -c docker");
}

// --- 安全なコマンドが誤検出されないことの確認 ---

#[test]
fn test_allow_eval_non_docker() {
    let (stdout, exit_code) = run_hook(&make_bash_input(r#"eval "echo hello""#));
    assert_eq!(exit_code, 0);
    assert!(
        stdout.trim().is_empty(),
        "eval without docker should be allowed"
    );
}

#[test]
fn test_allow_bash_c_non_docker() {
    let (stdout, exit_code) = run_hook(&make_bash_input(r#"bash -c "ls -la""#));
    assert_eq!(exit_code, 0);
    assert!(
        stdout.trim().is_empty(),
        "bash -c without docker should be allowed"
    );
}

// --- 複合パターン ---

#[test]
fn test_deny_chained_eval_docker() {
    let (stdout, exit_code) = run_hook(&make_bash_input(
        r#"cd /tmp && eval "docker run -v /etc:/data ubuntu""#,
    ));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "chained eval docker");
}

#[test]
fn test_deny_double_slash_path() {
    let (stdout, exit_code) = run_hook(&make_bash_input(
        "docker run -v //etc//passwd:/data ubuntu",
    ));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "double-slash path //etc//passwd");
}

// --- 新規: 名前空間分離フラグのテスト ---

#[test]
fn test_deny_userns_host() {
    let (stdout, exit_code) =
        run_hook(&make_bash_input("docker run --userns=host ubuntu"));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--userns=host");
}

#[test]
fn test_deny_userns_host_space() {
    let (stdout, exit_code) =
        run_hook(&make_bash_input("docker run --userns host ubuntu"));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--userns host (space)");
}

#[test]
fn test_deny_cgroupns_host() {
    let (stdout, exit_code) =
        run_hook(&make_bash_input("docker run --cgroupns=host ubuntu"));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--cgroupns=host");
}

#[test]
fn test_deny_ipc_host() {
    let (stdout, exit_code) =
        run_hook(&make_bash_input("docker run --ipc=host ubuntu"));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--ipc=host");
}

// --- 新規: --volumes-from テスト ---

fn assert_ask(stdout: &str, msg: &str) {
    let output: serde_json::Value =
        serde_json::from_str(stdout.trim()).unwrap_or_else(|_| panic!("Expected JSON for: {}", msg));
    assert_eq!(
        output["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("ask"),
        "Expected ask for: {}",
        msg
    );
}

#[test]
fn test_ask_volumes_from() {
    let (stdout, exit_code) =
        run_hook(&make_bash_input("docker run --volumes-from=mycontainer ubuntu"));
    assert_eq!(exit_code, 0);
    assert_ask(&stdout, "--volumes-from should ask");
}

// --- 新規: docker cp テスト ---

#[test]
fn test_deny_docker_cp_outside_home() {
    let (stdout, exit_code) =
        run_hook(&make_bash_input("docker cp /etc/passwd mycontainer:/tmp/"));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "docker cp from /etc/passwd");
}

#[test]
fn test_allow_docker_cp_home() {
    let home = dirs::home_dir().unwrap().to_string_lossy().to_string();
    let cmd = format!("docker cp {}/file.txt mycontainer:/tmp/", home);
    let (stdout, exit_code) = run_hook(&make_bash_input(&cmd));
    assert_eq!(exit_code, 0);
    assert!(
        stdout.trim().is_empty(),
        "docker cp from $HOME should be allowed"
    );
}

// --- 新規: docker build コンテキストパステスト ---

#[test]
fn test_deny_docker_build_outside_home() {
    let (stdout, exit_code) =
        run_hook(&make_bash_input("docker build -t myapp /etc"));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "docker build with context /etc");
}

#[test]
fn test_allow_docker_build_home() {
    let home = dirs::home_dir().unwrap().to_string_lossy().to_string();
    let cmd = format!("docker build -t myapp {}/project", home);
    let (stdout, exit_code) = run_hook(&make_bash_input(&cmd));
    assert_eq!(exit_code, 0);
    assert!(
        stdout.trim().is_empty(),
        "docker build with $HOME context should be allowed"
    );
}

// --- 新規: 改行によるコマンド分割テスト ---

#[test]
fn test_deny_newline_separated_docker() {
    let (stdout, exit_code) = run_hook(&make_bash_input(
        "echo ok\ndocker run -v /etc:/data ubuntu",
    ));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "newline-separated docker command");
}

// --- 新規: Compose 危険設定テスト ---

#[test]
fn test_deny_compose_privileged() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("compose.yml"),
        "services:\n  web:\n    image: ubuntu\n    privileged: true\n",
    )
    .unwrap();

    let input = serde_json::json!({
        "session_id": "test-session",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": "docker compose up",
            "description": "test"
        },
        "cwd": dir.path().to_str().unwrap()
    })
    .to_string();

    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "compose with privileged: true");
}

#[test]
fn test_deny_compose_network_mode_host() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("compose.yml"),
        "services:\n  web:\n    image: ubuntu\n    network_mode: host\n",
    )
    .unwrap();

    let input = serde_json::json!({
        "session_id": "test-session",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": "docker compose up",
            "description": "test"
        },
        "cwd": dir.path().to_str().unwrap()
    })
    .to_string();

    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "compose with network_mode: host");
}

#[test]
fn test_deny_compose_cap_add() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("compose.yml"),
        "services:\n  web:\n    image: ubuntu\n    cap_add:\n      - SYS_ADMIN\n",
    )
    .unwrap();

    let input = serde_json::json!({
        "session_id": "test-session",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": "docker compose up",
            "description": "test"
        },
        "cwd": dir.path().to_str().unwrap()
    })
    .to_string();

    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "compose with cap_add: SYS_ADMIN");
}
