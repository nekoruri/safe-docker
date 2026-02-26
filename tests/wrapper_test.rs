use std::process::{Command, Stdio};

fn home_dir() -> String {
    dirs::home_dir().unwrap().to_string_lossy().to_string()
}

/// ラッパーモードで safe-docker を実行するヘルパー
fn run_wrapper(args: &[&str]) -> (String, String, i32) {
    run_wrapper_with_env(args, &[])
}

/// 環境変数付きでラッパーモードを実行
fn run_wrapper_with_env(args: &[&str], env_vars: &[(&str, &str)]) -> (String, String, i32) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_safe-docker"));
    for arg in args {
        cmd.arg(arg);
    }
    // モック docker として /bin/echo を使用
    cmd.env("SAFE_DOCKER_DOCKER_PATH", "/bin/echo");
    // 再帰防止の環境変数をクリア
    cmd.env_remove("SAFE_DOCKER_ACTIVE");
    cmd.env_remove("SAFE_DOCKER_BYPASS");
    cmd.env_remove("SAFE_DOCKER_ASK");
    for (key, value) in env_vars {
        cmd.env(key, value);
    }
    let output = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to spawn safe-docker");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(-1);
    (stdout, stderr, exit_code)
}

// --- Allow テスト ---

#[test]
fn test_wrapper_allow_run_no_mounts() {
    let (stdout, _stderr, exit_code) = run_wrapper(&["run", "ubuntu", "echo", "hello"]);
    assert_eq!(exit_code, 0);
    // /bin/echo がモック docker として実行され、引数がそのまま stdout に出力される
    assert!(
        stdout.contains("run ubuntu echo hello"),
        "Expected echo output, got: {}",
        stdout
    );
}

#[test]
fn test_wrapper_allow_ps() {
    let (stdout, _stderr, exit_code) = run_wrapper(&["ps"]);
    assert_eq!(exit_code, 0);
    assert!(stdout.contains("ps"));
}

#[test]
fn test_wrapper_allow_home_mount() {
    let mount_arg = format!("{}/projects:/app", home_dir());
    let (stdout, _stderr, exit_code) =
        run_wrapper(&["run", "-v", &mount_arg, "ubuntu", "echo", "hello"]);
    assert_eq!(exit_code, 0);
    assert!(stdout.contains("run"));
}

// --- Deny テスト ---

#[test]
fn test_wrapper_deny_mount_etc() {
    let (_stdout, stderr, exit_code) = run_wrapper(&["run", "-v", "/etc:/data", "ubuntu"]);
    assert_eq!(exit_code, 1);
    assert!(
        stderr.contains("[safe-docker]"),
        "Expected error message, got: {}",
        stderr
    );
    assert!(
        stderr.contains("outside $HOME"),
        "Expected path denial reason, got: {}",
        stderr
    );
}

#[test]
fn test_wrapper_deny_privileged() {
    let (_stdout, stderr, exit_code) = run_wrapper(&["run", "--privileged", "ubuntu"]);
    assert_eq!(exit_code, 1);
    assert!(stderr.contains("privileged"));
}

#[test]
fn test_wrapper_deny_cap_add() {
    let (_stdout, stderr, exit_code) = run_wrapper(&["run", "--cap-add", "SYS_ADMIN", "ubuntu"]);
    assert_eq!(exit_code, 1);
    assert!(stderr.contains("cap-add") || stderr.contains("SYS_ADMIN"));
}

#[test]
fn test_wrapper_deny_device() {
    let (_stdout, stderr, exit_code) = run_wrapper(&["run", "--device", "/dev/sda", "ubuntu"]);
    assert_eq!(exit_code, 1);
    assert!(stderr.contains("device"));
}

#[test]
fn test_wrapper_deny_network_host() {
    let (_stdout, stderr, exit_code) = run_wrapper(&["run", "--network=host", "ubuntu"]);
    assert_eq!(exit_code, 1);
    assert!(stderr.contains("network") || stderr.contains("host"));
}

#[test]
fn test_wrapper_deny_pid_host() {
    let (_stdout, stderr, exit_code) = run_wrapper(&["run", "--pid=host", "ubuntu"]);
    assert_eq!(exit_code, 1);
    assert!(stderr.contains("pid") || stderr.contains("host"));
}

#[test]
fn test_wrapper_deny_mount_root() {
    let (_stdout, _stderr, exit_code) = run_wrapper(&["run", "-v", "/:/host", "ubuntu"]);
    assert_eq!(exit_code, 1);
}

#[test]
fn test_wrapper_deny_docker_socket() {
    let (_stdout, stderr, exit_code) = run_wrapper(&[
        "run",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
        "ubuntu",
    ]);
    assert_eq!(exit_code, 1);
    assert!(
        stderr.contains("[safe-docker]"),
        "Expected error message for docker socket mount"
    );
}

// --- --dry-run テスト ---

#[test]
fn test_wrapper_dry_run_allow() {
    let (_stdout, stderr, exit_code) =
        run_wrapper(&["--dry-run", "run", "ubuntu", "echo", "hello"]);
    assert_eq!(exit_code, 0);
    assert!(
        stderr.contains("Decision: allow"),
        "Expected allow decision in dry-run, got: {}",
        stderr
    );
    assert!(stderr.contains("would execute"));
}

#[test]
fn test_wrapper_dry_run_deny() {
    let (_stdout, stderr, exit_code) = run_wrapper(&["--dry-run", "run", "--privileged", "ubuntu"]);
    assert_eq!(exit_code, 1);
    assert!(
        stderr.contains("Decision: deny"),
        "Expected deny decision in dry-run, got: {}",
        stderr
    );
    assert!(stderr.contains("privileged"));
}

#[test]
fn test_wrapper_dry_run_does_not_execute() {
    // --dry-run では docker を実行しないため stdout は空
    let (stdout, _stderr, _exit_code) =
        run_wrapper(&["--dry-run", "run", "ubuntu", "echo", "hello"]);
    assert!(
        stdout.trim().is_empty(),
        "dry-run should not produce stdout from docker execution, got: {}",
        stdout
    );
}

// --- bypass モード ---

#[test]
fn test_wrapper_bypass() {
    let (stdout, _stderr, exit_code) = run_wrapper_with_env(
        &["run", "--privileged", "ubuntu"],
        &[("SAFE_DOCKER_BYPASS", "1")],
    );
    assert_eq!(exit_code, 0);
    // bypass: チェックをスキップして docker を実行
    assert!(
        stdout.contains("run --privileged ubuntu"),
        "Expected docker execution in bypass mode, got: {}",
        stdout
    );
}

// --- 再帰呼び出し防止 ---

#[test]
fn test_wrapper_recursion_prevention() {
    let (stdout, _stderr, exit_code) = run_wrapper_with_env(
        &["run", "--privileged", "ubuntu"],
        &[("SAFE_DOCKER_ACTIVE", "1")],
    );
    assert_eq!(exit_code, 0);
    // SAFE_DOCKER_ACTIVE=1 → チェックスキップ
    assert!(
        stdout.contains("run --privileged ubuntu"),
        "Expected direct docker execution when SAFE_DOCKER_ACTIVE=1, got: {}",
        stdout
    );
}

// --- compose テスト ---

#[test]
fn test_wrapper_compose_exec_allow() {
    let (stdout, _stderr, exit_code) = run_wrapper(&["compose", "exec", "web", "bash"]);
    assert_eq!(exit_code, 0);
    assert!(stdout.contains("compose exec web bash"));
}

// --- --help / --version ---

#[test]
fn test_wrapper_help() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_safe-docker"));
    cmd.arg("--help");
    let output = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to spawn safe-docker");

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(-1);
    assert_eq!(exit_code, 0);
    assert!(stderr.contains("safe-docker"));
    assert!(stderr.contains("USAGE"));
}

#[test]
fn test_wrapper_version() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_safe-docker"));
    cmd.arg("--version");
    let output = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to spawn safe-docker");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let exit_code = output.status.code().unwrap_or(-1);
    assert_eq!(exit_code, 0);
    assert!(stdout.contains("safe-docker"));
}

// --- multiple violations ---

#[test]
fn test_wrapper_deny_multiple_violations() {
    let (_stdout, stderr, exit_code) =
        run_wrapper(&["run", "--privileged", "-v", "/etc:/data", "ubuntu"]);
    assert_eq!(exit_code, 1);
    assert!(
        stderr.contains("Multiple issues") || stderr.contains("privileged"),
        "Expected multiple violations message, got: {}",
        stderr
    );
}

// --- argv[0] 透過モード テスト ---
// symlink テストは環境に依存するため、統合テストでは evaluate_docker_args のユニットテストでカバー

// --- 環境変数による docker パスの上書き ---

#[test]
fn test_wrapper_custom_docker_path() {
    // /bin/true をモック docker として使用 → 成功するが出力は空
    let (stdout, _stderr, exit_code) =
        run_wrapper_with_env(&["ps"], &[("SAFE_DOCKER_DOCKER_PATH", "/bin/true")]);
    assert_eq!(exit_code, 0);
    assert!(stdout.trim().is_empty());
}

// --- build コンテキストのテスト ---

#[test]
fn test_wrapper_deny_build_outside_home() {
    let (_stdout, stderr, exit_code) = run_wrapper(&["build", "-t", "myapp", "/etc"]);
    assert_eq!(exit_code, 1);
    assert!(
        stderr.contains("[safe-docker]"),
        "Expected deny for build outside $HOME: {}",
        stderr
    );
}

#[test]
fn test_wrapper_allow_build_cwd() {
    let (stdout, _stderr, exit_code) = run_wrapper(&["build", "-t", "myapp", "."]);
    assert_eq!(exit_code, 0);
    assert!(stdout.contains("build"));
}

// --- exec テスト ---

#[test]
fn test_wrapper_deny_exec_privileged() {
    let (_stdout, stderr, exit_code) =
        run_wrapper(&["exec", "--privileged", "mycontainer", "bash"]);
    assert_eq!(exit_code, 1);
    assert!(stderr.contains("privileged"));
}

#[test]
fn test_wrapper_allow_exec_no_flags() {
    let (stdout, _stderr, exit_code) = run_wrapper(&["exec", "mycontainer", "ls"]);
    assert_eq!(exit_code, 0);
    assert!(stdout.contains("exec mycontainer ls"));
}

// --- mount 系バリエーション ---

#[test]
fn test_wrapper_deny_mount_type_bind() {
    let (_stdout, _stderr, exit_code) = run_wrapper(&[
        "run",
        "--mount",
        "type=bind,source=/etc,target=/data",
        "ubuntu",
    ]);
    assert_eq!(exit_code, 1);
}

#[test]
fn test_wrapper_allow_tilde_mount() {
    let (stdout, _stderr, exit_code) = run_wrapper(&["run", "-v", "~/projects:/app", "ubuntu"]);
    assert_eq!(exit_code, 0);
    assert!(stdout.contains("run"));
}

// --- verbose テスト (deny 時の tip 表示) ---

#[test]
fn test_wrapper_verbose_deny_privileged() {
    let (_stdout, stderr, exit_code) = run_wrapper(&["--verbose", "run", "--privileged", "ubuntu"]);
    assert_eq!(exit_code, 1);
    assert!(
        stderr.contains("Tip:"),
        "Expected tip in verbose mode: {}",
        stderr
    );
    // --privileged に対して --cap-add を提案するか確認
    assert!(
        stderr.contains("--cap-add"),
        "Expected --cap-add suggestion for --privileged, got: {}",
        stderr
    );
}

#[test]
fn test_wrapper_verbose_deny_mount_outside_home() {
    let (_stdout, stderr, exit_code) =
        run_wrapper(&["--verbose", "run", "-v", "/etc:/data", "ubuntu"]);
    assert_eq!(exit_code, 1);
    assert!(
        stderr.contains("allowed_paths"),
        "Expected allowed_paths tip for path denial, got: {}",
        stderr
    );
}

#[test]
fn test_wrapper_verbose_deny_docker_socket() {
    let (_stdout, stderr, exit_code) = run_wrapper(&[
        "--verbose",
        "run",
        "-v",
        "/var/run/docker.sock:/var/run/docker.sock",
        "ubuntu",
    ]);
    assert_eq!(exit_code, 1);
    assert!(
        stderr.contains("block_docker_socket"),
        "Expected block_docker_socket tip, got: {}",
        stderr
    );
}

#[test]
fn test_wrapper_verbose_deny_network_host() {
    let (_stdout, stderr, exit_code) =
        run_wrapper(&["--verbose", "run", "--network=host", "ubuntu"]);
    assert_eq!(exit_code, 1);
    assert!(
        stderr.contains("blocked_flags"),
        "Expected blocked_flags tip for namespace flag, got: {}",
        stderr
    );
}

// --- -v は docker の volume フラグとして処理される ---

#[test]
fn test_wrapper_v_flag_is_docker_volume() {
    // -v ~/projects:/app は docker の volume フラグ、safe-docker の --verbose ではない
    let (stdout, _stderr, exit_code) = run_wrapper(&["run", "-v", "~/projects:/app", "ubuntu"]);
    assert_eq!(exit_code, 0);
    // -v がフィルタされずに docker に渡されることを確認
    assert!(
        stdout.contains("-v"),
        "Expected -v to be passed to docker, got: {}",
        stdout
    );
}

// --- --docker-path CLI オプション ---

#[test]
fn test_wrapper_docker_path_cli_option() {
    // --docker-path で指定した docker バイナリを使用する
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_safe-docker"));
    cmd.args(["--docker-path", "/bin/echo", "run", "ubuntu", "hello"]);
    cmd.env_remove("SAFE_DOCKER_ACTIVE");
    cmd.env_remove("SAFE_DOCKER_BYPASS");
    cmd.env_remove("SAFE_DOCKER_DOCKER_PATH");
    let output = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to spawn safe-docker");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let exit_code = output.status.code().unwrap_or(-1);
    assert_eq!(exit_code, 0);
    // --docker-path は docker に渡されず、/bin/echo が docker として使われる
    assert!(
        stdout.contains("run ubuntu hello"),
        "Expected echo output from --docker-path override, got: {}",
        stdout
    );
    assert!(
        !stdout.contains("--docker-path"),
        "--docker-path should be stripped from docker args, got: {}",
        stdout
    );
}

#[test]
fn test_wrapper_docker_path_not_passed_to_docker() {
    // --docker-path の値が docker 引数として渡されないことを確認
    let (stdout, _stderr, exit_code) = run_wrapper(&["--docker-path", "/bin/echo", "ps"]);
    assert_eq!(exit_code, 0);
    assert!(
        !stdout.contains("--docker-path"),
        "--docker-path should not appear in docker args: {}",
        stdout
    );
    assert!(
        !stdout.contains("/bin/echo"),
        "docker path value should not appear in docker args: {}",
        stdout
    );
}

// --- --dry-run + ask ---

#[test]
fn test_wrapper_dry_run_ask() {
    let mount_arg = format!("{}/.ssh:/keys", home_dir());
    let (_stdout, stderr, exit_code) =
        run_wrapper(&["--dry-run", "run", "-v", &mount_arg, "ubuntu"]);
    assert_eq!(exit_code, 0);
    assert!(
        stderr.contains("Decision: ask"),
        "Expected ask decision in dry-run, got: {}",
        stderr
    );
}

// --- --help にオプション情報が含まれる ---

#[test]
fn test_wrapper_help_contains_docker_path() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_safe-docker"));
    cmd.arg("--help");
    let output = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to spawn safe-docker");

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        stderr.contains("--docker-path"),
        "Help should mention --docker-path: {}",
        stderr
    );
}

// --- エッジケーステスト ---

#[test]
fn test_wrapper_docker_path_nonexistent_falls_back_to_path() {
    // --docker-path に存在しないパスを指定 → PATH からフォールバック検索
    // find_real_docker() は env → config → PATH の順で探すため、
    // config に不正パスがあっても PATH に docker があれば成功する
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_safe-docker"));
    cmd.args(["--docker-path", "/nonexistent/docker", "--dry-run", "ps"]);
    cmd.env_remove("SAFE_DOCKER_ACTIVE");
    cmd.env_remove("SAFE_DOCKER_BYPASS");
    cmd.env_remove("SAFE_DOCKER_DOCKER_PATH");
    let output = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to spawn safe-docker");

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let exit_code = output.status.code().unwrap_or(-1);
    // PATH に docker がある環境ではフォールバック成功 → allow
    assert_eq!(
        exit_code, 0,
        "Nonexistent --docker-path should fall back to PATH, stderr: {}",
        stderr
    );
    assert!(
        stderr.contains("Decision: allow"),
        "Expected allow with fallback, got: {}",
        stderr
    );
}

#[test]
fn test_wrapper_env_docker_path_overrides_cli_docker_path() {
    // SAFE_DOCKER_DOCKER_PATH 環境変数は --docker-path CLI より優先（env > config > PATH）
    // ただし --docker-path は config を上書きするだけなので、env が最優先
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_safe-docker"));
    cmd.args(["--docker-path", "/nonexistent/docker", "ps"]);
    // env で /bin/echo を指定 → env が勝つ
    cmd.env("SAFE_DOCKER_DOCKER_PATH", "/bin/echo");
    cmd.env_remove("SAFE_DOCKER_ACTIVE");
    cmd.env_remove("SAFE_DOCKER_BYPASS");
    let output = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to spawn safe-docker");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let exit_code = output.status.code().unwrap_or(-1);
    assert_eq!(
        exit_code,
        0,
        "Env var should override --docker-path, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("ps"),
        "Expected /bin/echo to run with 'ps', got: {}",
        stdout
    );
}

#[test]
fn test_wrapper_safe_docker_ask_invalid_value() {
    // SAFE_DOCKER_ASK に不正な値 → config のデフォルト (deny) にフォールバック
    let mount_arg = format!("{}/.ssh:/keys", home_dir());
    let (_stdout, stderr, exit_code) = run_wrapper_with_env(
        &["run", "-v", &mount_arg, "ubuntu"],
        &[("SAFE_DOCKER_ASK", "invalid_value")],
    );
    // 非 TTY 環境で ask → deny（不正な値は無視して config デフォルト = deny）
    assert_eq!(
        exit_code, 1,
        "Invalid SAFE_DOCKER_ASK should fall back to deny, stderr: {}",
        stderr
    );
}

#[test]
fn test_wrapper_safe_docker_ask_allow() {
    // SAFE_DOCKER_ASK=allow → 非対話環境で ask 判定が allow に
    let mount_arg = format!("{}/.ssh:/keys", home_dir());
    let (stdout, stderr, exit_code) = run_wrapper_with_env(
        &["run", "-v", &mount_arg, "ubuntu"],
        &[("SAFE_DOCKER_ASK", "allow")],
    );
    assert_eq!(
        exit_code, 0,
        "SAFE_DOCKER_ASK=allow should proceed, stderr: {}",
        stderr
    );
    assert!(
        stderr.contains("Non-interactive: proceeding"),
        "Expected non-interactive allow message, got stderr: {}",
        stderr
    );
    assert!(
        stdout.contains("run"),
        "Expected docker execution, got stdout: {}",
        stdout
    );
}

#[test]
fn test_wrapper_safe_docker_ask_deny() {
    // SAFE_DOCKER_ASK=deny → 非対話環境で ask 判定が deny に
    let mount_arg = format!("{}/.ssh:/keys", home_dir());
    let (_stdout, stderr, exit_code) = run_wrapper_with_env(
        &["run", "-v", &mount_arg, "ubuntu"],
        &[("SAFE_DOCKER_ASK", "deny")],
    );
    assert_eq!(
        exit_code, 1,
        "SAFE_DOCKER_ASK=deny should block, stderr: {}",
        stderr
    );
    assert!(
        stderr.contains("Non-interactive: blocked"),
        "Expected non-interactive deny message, got stderr: {}",
        stderr
    );
}

#[test]
fn test_wrapper_no_args_is_hook_mode() {
    // 引数なしで起動 → hook モード（stdin から JSON を期待）
    // stdin が null なので即終了（エラーにならない）
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_safe-docker"));
    cmd.env_remove("SAFE_DOCKER_ACTIVE");
    cmd.env_remove("SAFE_DOCKER_BYPASS");
    cmd.env_remove("SAFE_DOCKER_DOCKER_PATH");
    let output = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to spawn safe-docker");

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    // hook モードで stdin が空/無効 → deny 出力
    assert!(
        stdout.contains("deny") || stdout.is_empty(),
        "No-args should enter hook mode (deny on null stdin or empty), got stdout: {}",
        stdout
    );
}

// --- --check-config にラッパー設定が含まれる ---

#[test]
fn test_check_config_shows_wrapper_settings() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_safe-docker"));
    cmd.arg("--check-config");
    let output = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to spawn safe-docker");

    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert!(
        stderr.contains("wrapper.docker_path"),
        "check-config should show wrapper.docker_path: {}",
        stderr
    );
    assert!(
        stderr.contains("wrapper.non_interactive_ask"),
        "check-config should show wrapper.non_interactive_ask: {}",
        stderr
    );
}

// --- Phase 5a: --uts=host ---

#[test]
fn test_wrapper_deny_uts_host() {
    let (_, stderr, exit_code) = run_wrapper(&["run", "--uts=host", "ubuntu"]);
    assert_eq!(exit_code, 1);
    assert!(
        stderr.contains("--uts=host"),
        "--uts=host should be denied: {}",
        stderr
    );
}

#[test]
fn test_wrapper_deny_uts_host_space() {
    let (_, stderr, exit_code) = run_wrapper(&["run", "--uts", "host", "ubuntu"]);
    assert_eq!(exit_code, 1);
    assert!(
        stderr.contains("--uts=host"),
        "--uts host (space) should be denied: {}",
        stderr
    );
}

// --- Phase 5b: --env-file ---

#[test]
fn test_wrapper_deny_env_file_outside_home() {
    let (_, stderr, exit_code) = run_wrapper(&["run", "--env-file", "/etc/shadow", "ubuntu"]);
    assert_eq!(exit_code, 1);
    assert!(
        stderr.contains("outside $HOME") || stderr.contains("/etc/shadow"),
        "--env-file /etc/shadow should be denied: {}",
        stderr
    );
}

#[test]
fn test_wrapper_deny_env_file_equals_outside_home() {
    let (_, stderr, exit_code) = run_wrapper(&["run", "--env-file=/etc/secrets.env", "ubuntu"]);
    assert_eq!(exit_code, 1);
    assert!(
        stderr.contains("outside $HOME") || stderr.contains("/etc/secrets"),
        "--env-file=/etc/secrets.env should be denied: {}",
        stderr
    );
}

#[test]
fn test_wrapper_allow_env_file_inside_home() {
    let (stdout, _, exit_code) = run_wrapper(&[
        "run",
        "--env-file",
        &format!("{}/projects/.env", home_dir()),
        "ubuntu",
    ]);
    assert_eq!(exit_code, 0);
    assert!(
        stdout.contains("ubuntu"),
        "--env-file inside $HOME should be allowed"
    );
}

// --- Phase 5b: --label-file ---

#[test]
fn test_wrapper_deny_label_file_outside_home() {
    let (_, stderr, exit_code) = run_wrapper(&["run", "--label-file", "/etc/labels", "ubuntu"]);
    assert_eq!(exit_code, 1);
    assert!(
        stderr.contains("outside $HOME") || stderr.contains("/etc/labels"),
        "--label-file /etc/labels should be denied: {}",
        stderr
    );
}

// --- Phase 5b: seccomp profile path ---

#[test]
fn test_wrapper_deny_seccomp_profile_outside_home() {
    let (_, stderr, exit_code) = run_wrapper(&[
        "run",
        "--security-opt",
        "seccomp=/etc/docker/seccomp.json",
        "ubuntu",
    ]);
    assert_eq!(exit_code, 1);
    assert!(
        stderr.contains("outside $HOME") || stderr.contains("seccomp") || stderr.contains("/etc"),
        "seccomp profile outside $HOME should be denied: {}",
        stderr
    );
}

// --- Phase 5c: blocked capabilities ---

#[test]
fn test_wrapper_deny_cap_add_net_admin() {
    let (_, stderr, exit_code) = run_wrapper(&["run", "--cap-add", "NET_ADMIN", "ubuntu"]);
    assert_eq!(exit_code, 1);
    assert!(
        stderr.contains("NET_ADMIN"),
        "--cap-add NET_ADMIN should be denied: {}",
        stderr
    );
}

#[test]
fn test_wrapper_deny_cap_add_dac_read_search() {
    let (_, stderr, exit_code) = run_wrapper(&["run", "--cap-add=DAC_READ_SEARCH", "ubuntu"]);
    assert_eq!(exit_code, 1);
    assert!(
        stderr.contains("DAC_READ_SEARCH"),
        "--cap-add=DAC_READ_SEARCH should be denied: {}",
        stderr
    );
}

#[test]
fn test_wrapper_deny_cap_add_bpf() {
    let (_, stderr, exit_code) = run_wrapper(&["run", "--cap-add", "BPF", "ubuntu"]);
    assert_eq!(exit_code, 1);
    assert!(
        stderr.contains("BPF"),
        "--cap-add BPF should be denied: {}",
        stderr
    );
}
