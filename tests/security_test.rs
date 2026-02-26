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
    let output: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|_| panic!("Expected JSON for: {}", msg));
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
    let (stdout, exit_code) = run_hook(&make_bash_input(
        r#"eval "docker run -v /etc:/data ubuntu""#,
    ));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "eval docker run");
}

#[test]
fn test_deny_bash_c_docker() {
    let (stdout, exit_code) = run_hook(&make_bash_input(
        r#"bash -c "docker run -v /etc:/data ubuntu""#,
    ));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "bash -c docker run");
}

#[test]
fn test_deny_sh_c_docker_single_quote() {
    let (stdout, exit_code) = run_hook(&make_bash_input("sh -c 'docker run -v /etc:/data ubuntu'"));
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
    let (stdout, exit_code) = run_hook(&make_bash_input("docker run --net host ubuntu"));
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
    let (stdout, exit_code) = run_hook(&make_bash_input("sudo docker run -v /etc:/data ubuntu"));
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
    let (stdout, exit_code) =
        run_hook(&make_bash_input("docker run -v //etc//passwd:/data ubuntu"));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "double-slash path //etc//passwd");
}

// --- docker buildx build テスト ---

#[test]
fn test_deny_buildx_build_outside_home() {
    let (stdout, exit_code) = run_hook(&make_bash_input("docker buildx build -t myapp /etc"));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "docker buildx build with context /etc");
}

// --- docker exec テスト ---

#[test]
fn test_deny_docker_exec_privileged() {
    let (stdout, exit_code) = run_hook(&make_bash_input(
        "docker exec --privileged mycontainer bash",
    ));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "docker exec --privileged");
}

// --- security-opt 拡充テスト ---

#[test]
fn test_deny_security_opt_systempaths_unconfined() {
    let (stdout, exit_code) = run_hook(&make_bash_input(
        "docker run --security-opt systempaths=unconfined ubuntu",
    ));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--security-opt systempaths=unconfined");
}

#[test]
fn test_deny_security_opt_no_new_privileges_false() {
    let (stdout, exit_code) = run_hook(&make_bash_input(
        "docker run --security-opt no-new-privileges=false ubuntu",
    ));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--security-opt no-new-privileges=false");
}

#[test]
fn test_deny_security_opt_no_new_privileges_colon_false() {
    let (stdout, exit_code) = run_hook(&make_bash_input(
        "docker run --security-opt no-new-privileges:false ubuntu",
    ));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--security-opt no-new-privileges:false");
}

// --- 名前空間分離フラグのテスト ---

#[test]
fn test_deny_userns_host() {
    let (stdout, exit_code) = run_hook(&make_bash_input("docker run --userns=host ubuntu"));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--userns=host");
}

#[test]
fn test_deny_userns_host_space() {
    let (stdout, exit_code) = run_hook(&make_bash_input("docker run --userns host ubuntu"));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--userns host (space)");
}

#[test]
fn test_deny_cgroupns_host() {
    let (stdout, exit_code) = run_hook(&make_bash_input("docker run --cgroupns=host ubuntu"));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--cgroupns=host");
}

#[test]
fn test_deny_ipc_host() {
    let (stdout, exit_code) = run_hook(&make_bash_input("docker run --ipc=host ubuntu"));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--ipc=host");
}

// --- 新規: --volumes-from テスト ---

fn assert_ask(stdout: &str, msg: &str) {
    let output: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|_| panic!("Expected JSON for: {}", msg));
    assert_eq!(
        output["hookSpecificOutput"]["permissionDecision"].as_str(),
        Some("ask"),
        "Expected ask for: {}",
        msg
    );
}

#[test]
fn test_ask_volumes_from() {
    let (stdout, exit_code) = run_hook(&make_bash_input(
        "docker run --volumes-from=mycontainer ubuntu",
    ));
    assert_eq!(exit_code, 0);
    assert_ask(&stdout, "--volumes-from should ask");
}

// --- 新規: docker cp テスト ---

#[test]
fn test_deny_docker_cp_outside_home() {
    let (stdout, exit_code) = run_hook(&make_bash_input("docker cp /etc/passwd mycontainer:/tmp/"));
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
    let (stdout, exit_code) = run_hook(&make_bash_input("docker build -t myapp /etc"));
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
    let (stdout, exit_code) =
        run_hook(&make_bash_input("echo ok\ndocker run -v /etc:/data ubuntu"));
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

// --- コンテナ間 namespace 共有テスト ---

#[test]
fn test_deny_network_container() {
    let (stdout, exit_code) =
        run_hook(&make_bash_input("docker run --network=container:db ubuntu"));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--network=container:db");
}

#[test]
fn test_deny_pid_container() {
    let (stdout, exit_code) = run_hook(&make_bash_input("docker run --pid=container:app ubuntu"));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--pid=container:app");
}

#[test]
fn test_deny_ipc_container() {
    let (stdout, exit_code) = run_hook(&make_bash_input("docker run --ipc=container:shm ubuntu"));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--ipc=container:shm");
}

// --- mount propagation テスト ---

#[test]
fn test_deny_volume_propagation_shared() {
    let home = dirs::home_dir().unwrap().to_string_lossy().to_string();
    let cmd = format!("docker run -v {}/data:/data:shared ubuntu", home);
    let (stdout, exit_code) = run_hook(&make_bash_input(&cmd));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "-v with shared propagation");
}

#[test]
fn test_deny_mount_propagation_rshared() {
    let home = dirs::home_dir().unwrap().to_string_lossy().to_string();
    let cmd = format!(
        "docker run --mount type=bind,source={}/data,target=/data,bind-propagation=rshared ubuntu",
        home
    );
    let (stdout, exit_code) = run_hook(&make_bash_input(&cmd));
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--mount with rshared propagation");
}

// --- Compose コンテナ間 namespace 共有テスト ---

#[test]
fn test_deny_compose_network_mode_container() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("compose.yml"),
        "services:\n  web:\n    image: ubuntu\n    network_mode: container:db\n",
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
    assert_deny(&stdout, "compose with network_mode: container:db");
}

#[test]
fn test_deny_compose_pid_container() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("compose.yml"),
        "services:\n  web:\n    image: ubuntu\n    pid: container:app\n",
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
    assert_deny(&stdout, "compose with pid: container:app");
}

// --- Phase 5a: --uts=host ---

#[test]
fn test_deny_uts_host() {
    let input = make_bash_input("docker run --uts=host ubuntu");
    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--uts=host");
}

#[test]
fn test_deny_uts_host_space() {
    let input = make_bash_input("docker run --uts host ubuntu");
    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--uts=host (space syntax)");
}

#[test]
fn test_deny_compose_uts_host() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("compose.yml"),
        "services:\n  web:\n    image: ubuntu\n    uts: host\n",
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
    assert_deny(&stdout, "compose with uts: host");
}

// --- Phase 5b: --env-file / --label-file パス検証 ---

#[test]
fn test_deny_env_file_outside_home() {
    let input = make_bash_input("docker run --env-file /etc/shadow ubuntu");
    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--env-file with path outside $HOME");
}

#[test]
fn test_deny_env_file_equals_outside_home() {
    let input = make_bash_input("docker run --env-file=/etc/secrets.env ubuntu");
    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--env-file= with path outside $HOME");
}

#[test]
fn test_deny_label_file_outside_home() {
    let input = make_bash_input("docker run --label-file /etc/labels ubuntu");
    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--label-file with path outside $HOME");
}

// --- Phase 5b: --security-opt seccomp=PATH ---

#[test]
fn test_deny_seccomp_profile_outside_home() {
    let input =
        make_bash_input("docker run --security-opt seccomp=/etc/docker/seccomp.json ubuntu");
    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "seccomp profile path outside $HOME");
}

// --- Phase 5c: blocked_capabilities 拡充 ---

#[test]
fn test_deny_cap_add_net_admin() {
    let input = make_bash_input("docker run --cap-add NET_ADMIN ubuntu");
    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--cap-add NET_ADMIN");
}

#[test]
fn test_deny_cap_add_dac_read_search() {
    let input = make_bash_input("docker run --cap-add DAC_READ_SEARCH ubuntu");
    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--cap-add DAC_READ_SEARCH");
}

#[test]
fn test_deny_cap_add_bpf() {
    let input = make_bash_input("docker run --cap-add BPF ubuntu");
    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--cap-add BPF");
}

#[test]
fn test_deny_cap_add_sys_boot() {
    let input = make_bash_input("docker run --cap-add SYS_BOOT ubuntu");
    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--cap-add SYS_BOOT");
}

#[test]
fn test_deny_cap_add_perfmon() {
    let input = make_bash_input("docker run --cap-add PERFMON ubuntu");
    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--cap-add PERFMON");
}

// --- is_flag_with_value 補完の E2E テスト ---

#[test]
fn test_env_file_does_not_eat_privileged() {
    // --env-file の値が is_flag_with_value に含まれない場合、
    // 次の --privileged がイメージ名として誤認されるバグを防ぐ
    let input = make_bash_input("docker run --env-file /tmp/env --privileged ubuntu");
    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--env-file should not eat --privileged flag");
}

// --- Phase 5d: --sysctl 危険値検出 ---

#[test]
fn test_deny_sysctl_kernel() {
    let input = make_bash_input("docker run --sysctl kernel.core_pattern=/tmp/exploit ubuntu");
    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--sysctl kernel.* should be denied");
}

#[test]
fn test_deny_sysctl_kernel_equals() {
    let input = make_bash_input("docker run --sysctl=kernel.shmmax=65536 ubuntu");
    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--sysctl=kernel.* should be denied");
}

#[test]
fn test_ask_sysctl_net() {
    let input = make_bash_input("docker run --sysctl net.ipv4.ip_forward=1 ubuntu");
    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert_ask(&stdout, "--sysctl net.* should ask");
}

#[test]
fn test_deny_compose_sysctl_kernel() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("compose.yml"),
        "services:\n  web:\n    image: ubuntu\n    sysctls:\n      - kernel.shmmax=65536\n",
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
    assert_deny(&stdout, "compose with kernel.* sysctl should be denied");
}

#[test]
fn test_ask_compose_sysctl_net() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("compose.yml"),
        "services:\n  web:\n    image: ubuntu\n    sysctls:\n      net.ipv4.ip_forward: 1\n",
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
    assert_ask(&stdout, "compose with net.* sysctl should ask");
}

// --- Phase 5d: --add-host メタデータ IP 検出 ---

#[test]
fn test_ask_add_host_metadata_ip() {
    let input = make_bash_input("docker run --add-host=metadata:169.254.169.254 ubuntu");
    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert_ask(&stdout, "--add-host with metadata IP should ask");
}

#[test]
fn test_ask_add_host_metadata_ip_space() {
    let input = make_bash_input("docker run --add-host metadata:169.254.169.254 ubuntu");
    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert_ask(&stdout, "--add-host with metadata IP (space) should ask");
}

#[test]
fn test_allow_add_host_normal_ip() {
    let input = make_bash_input("docker run --add-host myhost:192.168.1.1 ubuntu");
    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert!(
        stdout.trim().is_empty(),
        "add-host with normal IP should be allowed"
    );
}

// --- Phase 5d: CIS 5.2 --security-opt label:disable ---

#[test]
fn test_deny_security_opt_label_disable() {
    let input = make_bash_input("docker run --security-opt label=disable ubuntu");
    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--security-opt label=disable (CIS 5.2)");
}

#[test]
fn test_deny_security_opt_label_disable_colon() {
    let input = make_bash_input("docker run --security-opt label:disable ubuntu");
    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--security-opt label:disable (CIS 5.2)");
}

#[test]
fn test_deny_security_opt_label_disable_equals_syntax() {
    let input = make_bash_input("docker run --security-opt=label=disable ubuntu");
    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--security-opt=label=disable (CIS 5.2)");
}

// --- Phase 5d: --sysctl does not eat subsequent flags ---

#[test]
fn test_sysctl_does_not_eat_privileged() {
    let input = make_bash_input("docker run --sysctl net.core.somaxconn=1024 --privileged ubuntu");
    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--sysctl should not eat --privileged flag");
}

// --- Phase 5e: --build-arg secret pattern detection ---

#[test]
fn test_ask_build_arg_password() {
    let input = make_bash_input("docker build --build-arg DB_PASSWORD=secret123 -t myapp .");
    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert_ask(&stdout, "--build-arg with PASSWORD should ask");
}

#[test]
fn test_ask_build_arg_token_equals() {
    let input = make_bash_input("docker build --build-arg=API_TOKEN=abc123 -t myapp .");
    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert_ask(&stdout, "--build-arg=API_TOKEN should ask");
}

#[test]
fn test_allow_build_arg_safe() {
    let home = dirs::home_dir().unwrap().to_string_lossy().to_string();
    let cmd = format!(
        "docker build --build-arg APP_VERSION=1.0 -t myapp {}/project",
        home
    );
    let (stdout, exit_code) = run_hook(&make_bash_input(&cmd));
    assert_eq!(exit_code, 0);
    assert!(
        stdout.trim().is_empty(),
        "Non-secret build-arg should be allowed"
    );
}

// --- Phase 5e: --secret / --ssh path validation ---

#[test]
fn test_deny_build_secret_outside_home() {
    let input = make_bash_input("docker build --secret id=db,src=/etc/secrets/db.env -t myapp .");
    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--secret src outside $HOME should be denied");
}

#[test]
fn test_deny_build_ssh_outside_home() {
    let input = make_bash_input("docker build --ssh id=key,src=/etc/ssh/id_rsa -t myapp .");
    let (stdout, exit_code) = run_hook(&input);
    assert_eq!(exit_code, 0);
    assert_deny(&stdout, "--ssh src outside $HOME should be denied");
}

// --- Phase 5e: Compose include outside $HOME ---

#[test]
fn test_ask_compose_include_outside_home() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("compose.yml"),
        "include:\n  - /opt/shared/compose.yml\nservices:\n  web:\n    image: ubuntu\n",
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
    assert_ask(&stdout, "compose include outside $HOME should ask");
}

// --- Phase 5b: Compose env_file ---

#[test]
fn test_deny_compose_env_file_outside_home() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("compose.yml"),
        "services:\n  web:\n    image: ubuntu\n    env_file: /etc/secrets.env\n",
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
    assert_deny(&stdout, "compose env_file outside $HOME should deny");
}

#[test]
fn test_deny_compose_env_file_list_outside_home() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("compose.yml"),
        "services:\n  web:\n    image: ubuntu\n    env_file:\n      - .env\n      - /etc/secrets.env\n",
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
    assert_deny(
        &stdout,
        "compose env_file list with path outside $HOME should deny",
    );
}
