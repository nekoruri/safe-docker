/// プロパティベーステスト: ランダム入力でパニックやクラッシュが起きないことを検証。
/// hook バイナリに対して任意の JSON を投げてクラッシュしないことをテスト。
use proptest::prelude::*;
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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// 任意の文字列をコマンドとして入力してもパニック・クラッシュしない
    #[test]
    fn test_arbitrary_command_no_crash(cmd in ".*") {
        let input = make_bash_input(&cmd);
        let (_stdout, exit_code) = run_hook(&input);
        prop_assert_eq!(exit_code, 0, "Hook should always exit with 0");
    }

    /// 任意の JSON を stdin に入力してもクラッシュしない
    #[test]
    fn test_arbitrary_json_no_crash(json in "\\{[a-zA-Z0-9:,\"\\s]*\\}") {
        let (_stdout, exit_code) = run_hook(&json);
        prop_assert_eq!(exit_code, 0, "Hook should always exit with 0 for any JSON");
    }

    /// 完全にランダムなバイト列を入力してもクラッシュしない
    #[test]
    fn test_arbitrary_bytes_no_crash(data in "[\\x00-\\xff]{0,1000}") {
        let (_stdout, exit_code) = run_hook(&data);
        prop_assert_eq!(exit_code, 0, "Hook should always exit with 0 for any input");
    }

    /// docker コマンドに任意のフラグを渡してもパニックしない
    #[test]
    fn test_docker_with_random_flags(flags in "[a-zA-Z0-9 \\-=/.:~${}]{0,200}") {
        let cmd = format!("docker run {} ubuntu", flags);
        let input = make_bash_input(&cmd);
        let (_stdout, exit_code) = run_hook(&input);
        prop_assert_eq!(exit_code, 0, "Hook should always exit with 0");
    }

    /// docker compose に任意のフラグを渡してもパニックしない
    #[test]
    fn test_docker_compose_with_random_flags(flags in "[a-zA-Z0-9 \\-=/.:~]{0,200}") {
        let cmd = format!("docker compose {}", flags);
        let input = make_bash_input(&cmd);
        let (_stdout, exit_code) = run_hook(&input);
        prop_assert_eq!(exit_code, 0, "Hook should always exit with 0");
    }

    /// 任意のパス文字列でパニックしない
    #[test]
    fn test_docker_with_random_path(path in "[a-zA-Z0-9/\\.~${}\\-_]{0,200}") {
        let cmd = format!("docker run -v {}:/data ubuntu", path);
        let input = make_bash_input(&cmd);
        let (_stdout, exit_code) = run_hook(&input);
        prop_assert_eq!(exit_code, 0, "Hook should always exit with 0");
    }
}
