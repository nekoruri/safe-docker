use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use crate::config::{Config, NonInteractiveAsk};
use crate::hook::Decision;
use crate::{audit, docker_args, policy};

/// ラッパーモードのメインエントリポイント
///
/// docker 引数を評価し、Decision に応じてアクションを実行する。
/// - Allow → 本物の docker を exec
/// - Deny → stderr にエラー表示 + exit 1
/// - Ask → 対話的確認（非対話環境では設定に従う）
pub fn run(args: &[String], config: &Config) -> i32 {
    // 再帰呼び出し防止チェック
    if std::env::var("SAFE_DOCKER_ACTIVE").is_ok_and(|v| v == "1") {
        // 既に safe-docker 経由 → 本物の docker を直接実行
        let docker_path = match find_real_docker(config) {
            Some(p) => p,
            None => {
                eprintln!("[safe-docker] Error: could not find the real docker binary");
                return 1;
            }
        };
        exec_docker(&docker_path, args); // never returns
    }

    // バイパスモード
    if std::env::var("SAFE_DOCKER_BYPASS").is_ok_and(|v| v == "1") {
        let docker_path = match find_real_docker(config) {
            Some(p) => p,
            None => {
                eprintln!("[safe-docker] Error: could not find the real docker binary");
                return 1;
            }
        };
        exec_docker(&docker_path, args); // never returns
    }

    // CWD 取得
    let cwd = std::env::current_dir()
        .ok()
        .and_then(|p| p.to_str().map(String::from))
        .unwrap_or_else(|| ".".to_string());

    // --dry-run フラグの検出（safe-docker 固有オプション）
    let dry_run = args.iter().any(|a| a == "--dry-run");
    let verbose = args.iter().any(|a| a == "--verbose");

    // safe-docker 固有オプションを除去して docker に渡す引数を構築
    // (--docker-path は main.rs で事前に除去済み)
    let docker_args: Vec<String> = args
        .iter()
        .filter(|a| *a != "--dry-run" && *a != "--verbose")
        .cloned()
        .collect();

    // 監査ログ
    let audit_enabled = audit::is_enabled(&config.audit);
    let mut collector = if audit_enabled {
        Some(audit::AuditCollector::new())
    } else {
        None
    };

    // ポリシー評価
    let decision = evaluate_docker_args(&docker_args, config, &cwd, collector.as_mut());

    // 監査ログ出力
    if audit_enabled && let Some(ref collector) = collector {
        let command_str = format!("docker {}", docker_args.join(" "));
        let (decision_str, reason) = match &decision {
            Decision::Allow => ("allow", None),
            Decision::Deny(r) => ("deny", Some(r.as_str())),
            Decision::Ask(r) => ("ask", Some(r.as_str())),
        };

        let event = audit::build_event(&command_str, decision_str, reason, collector, None, &cwd, "wrapper");
        audit::emit(&event, &config.audit);
    }

    // Decision に応じたアクション
    match decision {
        Decision::Allow => {
            if dry_run {
                let docker_path = find_real_docker(config)
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_else(|| "docker".to_string());
                eprintln!(
                    "[safe-docker] Decision: allow (would execute: {} {})",
                    docker_path,
                    docker_args.join(" ")
                );
                return 0;
            }
            let docker_path = match find_real_docker(config) {
                Some(p) => p,
                None => {
                    eprintln!("[safe-docker] Error: could not find the real docker binary");
                    return 1;
                }
            };
            exec_docker(&docker_path, &docker_args); // never returns
        }
        Decision::Deny(reason) => {
            eprintln!("{}", reason);
            if verbose {
                eprintln!(
                    "  Tip: Check ~/.config/safe-docker/config.toml to adjust allowed paths or flags"
                );
            }
            if dry_run {
                eprintln!("[safe-docker] Decision: deny");
            }
            1
        }
        Decision::Ask(reason) => {
            if dry_run {
                eprintln!("{}", reason);
                eprintln!("[safe-docker] Decision: ask");
                return 0;
            }
            handle_ask(&reason, &docker_args, config, verbose)
        }
    }
}

/// OS 引数配列から直接ポリシー評価を行う
pub fn evaluate_docker_args(
    args: &[String],
    config: &Config,
    cwd: &str,
    mut collector: Option<&mut audit::AuditCollector>,
) -> Decision {
    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let docker_cmd = docker_args::parse_docker_args(&args_ref);

    if let Some(ref mut c) = collector {
        c.record_docker_command(&docker_cmd);
    }

    policy::evaluate(&docker_cmd, config, cwd)
}

/// Ask 判定時の対話的確認
fn handle_ask(reason: &str, docker_args: &[String], config: &Config, verbose: bool) -> i32 {
    use std::io::{self, BufRead, Write};

    eprintln!("{}", reason);

    let is_tty = std::io::stderr().is_terminal();

    if !is_tty {
        // 非対話環境: 環境変数 or 設定に従う
        let ask_policy = std::env::var("SAFE_DOCKER_ASK")
            .ok()
            .and_then(|v| match v.as_str() {
                "allow" => Some(NonInteractiveAsk::Allow),
                "deny" => Some(NonInteractiveAsk::Deny),
                _ => None,
            })
            .unwrap_or_else(|| config.wrapper.non_interactive_ask.clone());

        match ask_policy {
            NonInteractiveAsk::Allow => {
                eprintln!("[safe-docker] Non-interactive: proceeding (SAFE_DOCKER_ASK=allow)");
                let docker_path = match find_real_docker(config) {
                    Some(p) => p,
                    None => {
                        eprintln!("[safe-docker] Error: could not find the real docker binary");
                        return 1;
                    }
                };
                exec_docker(&docker_path, docker_args); // never returns
            }
            NonInteractiveAsk::Deny => {
                eprintln!("[safe-docker] Non-interactive: blocked (set SAFE_DOCKER_ASK=allow to override)");
                1
            }
        }
    } else {
        // 対話環境: ユーザーに確認
        eprint!("[safe-docker] Proceed? [y/N] ");
        io::stderr().flush().ok();

        let stdin = io::stdin();
        let mut line = String::new();
        if stdin.lock().read_line(&mut line).is_ok() {
            let answer = line.trim().to_lowercase();
            if answer == "y" || answer == "yes" {
                let docker_path = match find_real_docker(config) {
                    Some(p) => p,
                    None => {
                        eprintln!("[safe-docker] Error: could not find the real docker binary");
                        return 1;
                    }
                };
                exec_docker(&docker_path, docker_args); // never returns
            } else {
                if verbose {
                    eprintln!("[safe-docker] Aborted by user");
                }
                1
            }
        } else {
            eprintln!("[safe-docker] Failed to read input, blocking for safety");
            1
        }
    }
}

/// 本物の docker バイナリを検索する
///
/// 優先順位:
/// 1. 環境変数 SAFE_DOCKER_DOCKER_PATH
/// 2. 設定ファイルの wrapper.docker_path
/// 3. PATH から自動検索（自分自身を除外）
pub fn find_real_docker(config: &Config) -> Option<PathBuf> {
    // 1. 環境変数
    if let Ok(path) = std::env::var("SAFE_DOCKER_DOCKER_PATH")
        && !path.is_empty()
    {
        let p = PathBuf::from(&path);
        if p.exists() {
            return Some(p);
        }
        log::warn!(
            "SAFE_DOCKER_DOCKER_PATH={} does not exist, falling back",
            path
        );
    }

    // 2. 設定ファイル
    if !config.wrapper.docker_path.is_empty() {
        let p = PathBuf::from(&config.wrapper.docker_path);
        if p.exists() {
            return Some(p);
        }
        log::warn!(
            "wrapper.docker_path={} does not exist, falling back",
            config.wrapper.docker_path
        );
    }

    // 3. PATH 自動検索（自分自身を除外）
    find_docker_in_path()
}

/// PATH から docker バイナリを検索する（自分自身を除外）
fn find_docker_in_path() -> Option<PathBuf> {
    let self_exe = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::canonicalize(p).ok());

    let path_env = std::env::var("PATH").unwrap_or_default();
    for dir in path_env.split(':') {
        let candidate = Path::new(dir).join("docker");
        if candidate.exists() {
            // 自分自身でないか確認
            if let Some(ref self_path) = self_exe
                && let Ok(candidate_canonical) = std::fs::canonicalize(&candidate)
                && &candidate_canonical == self_path
            {
                continue;
            }
            return Some(candidate);
        }
    }
    None
}

/// 本物の docker を exec で実行する（プロセス置換）
///
/// 成功時は戻らない（exec でプロセスが置換される）。
/// 失敗時はエラーメッセージを表示して戻る。
fn exec_docker(docker_path: &Path, args: &[impl AsRef<std::ffi::OsStr>]) -> ! {
    use std::os::unix::process::CommandExt;

    // 再帰呼び出し防止の環境変数を設定
    let err = std::process::Command::new(docker_path)
        .args(args)
        .env("SAFE_DOCKER_ACTIVE", "1")
        .exec();

    // exec() は成功したら戻らない。ここに到達 = 失敗
    eprintln!(
        "[safe-docker] Error: failed to exec {}: {}",
        docker_path.display(),
        err
    );
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn default_config() -> Config {
        Config::default()
    }

    fn home_dir() -> String {
        dirs::home_dir().unwrap().to_string_lossy().to_string()
    }

    #[test]
    fn test_evaluate_docker_args_allow() {
        let args = vec!["run".to_string(), "ubuntu".to_string()];
        let config = default_config();
        let decision = evaluate_docker_args(&args, &config, "/tmp", None);
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_docker_args_deny_mount() {
        let args = vec![
            "run".to_string(),
            "-v".to_string(),
            "/etc:/data".to_string(),
            "ubuntu".to_string(),
        ];
        let config = default_config();
        let decision = evaluate_docker_args(&args, &config, "/tmp", None);
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn test_evaluate_docker_args_deny_privileged() {
        let args = vec![
            "run".to_string(),
            "--privileged".to_string(),
            "ubuntu".to_string(),
        ];
        let config = default_config();
        let decision = evaluate_docker_args(&args, &config, "/tmp", None);
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn test_evaluate_docker_args_allow_home_mount() {
        let args = vec![
            "run".to_string(),
            "-v".to_string(),
            format!("{}/projects:/app", home_dir()),
            "ubuntu".to_string(),
        ];
        let config = default_config();
        let decision = evaluate_docker_args(&args, &config, "/tmp", None);
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_docker_args_ask_sensitive() {
        let args = vec![
            "run".to_string(),
            "-v".to_string(),
            format!("{}/.ssh:/keys", home_dir()),
            "ubuntu".to_string(),
        ];
        let config = default_config();
        let decision = evaluate_docker_args(&args, &config, "/tmp", None);
        assert!(matches!(decision, Decision::Ask(_)));
    }

    #[test]
    fn test_evaluate_docker_args_compose() {
        let args = vec!["compose".to_string(), "exec".to_string(), "web".to_string()];
        let config = default_config();
        let decision = evaluate_docker_args(&args, &config, "/tmp", None);
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_docker_args_with_collector() {
        let args = vec![
            "run".to_string(),
            "-v".to_string(),
            "/etc:/data".to_string(),
            "ubuntu".to_string(),
        ];
        let config = default_config();
        let mut collector = audit::AuditCollector::new();
        let _decision = evaluate_docker_args(&args, &config, "/tmp", Some(&mut collector));
        assert_eq!(collector.docker_subcommands, vec!["run"]);
        assert_eq!(collector.images, vec!["ubuntu"]);
        assert_eq!(collector.bind_mounts, vec!["/etc"]);
    }

    #[test]
    fn test_find_real_docker_env_var() {
        let config = default_config();
        // /usr/bin/docker が存在する場合のテスト
        if Path::new("/usr/bin/docker").exists() {
            unsafe { std::env::set_var("SAFE_DOCKER_DOCKER_PATH", "/usr/bin/docker") };
            let result = find_real_docker(&config);
            assert_eq!(result, Some(PathBuf::from("/usr/bin/docker")));
            unsafe { std::env::remove_var("SAFE_DOCKER_DOCKER_PATH") };
        }
    }

    #[test]
    fn test_find_real_docker_config() {
        let mut config = default_config();
        // 存在するパスでテスト
        if Path::new("/usr/bin/docker").exists() {
            config.wrapper.docker_path = "/usr/bin/docker".to_string();
            let result = find_real_docker(&config);
            assert_eq!(result, Some(PathBuf::from("/usr/bin/docker")));
        }
    }

    #[test]
    fn test_find_real_docker_nonexistent_fallback() {
        let mut config = default_config();
        config.wrapper.docker_path = "/nonexistent/docker".to_string();
        // 設定パスが存在しない場合、PATH から探す
        let _result = find_real_docker(&config);
        // PATH に docker があるかは環境次第なので結果のアサートは省略
    }

    #[test]
    fn test_evaluate_ps_allow() {
        let args = vec!["ps".to_string()];
        let config = default_config();
        let decision = evaluate_docker_args(&args, &config, "/tmp", None);
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_dangerous_flags() {
        let args = vec![
            "run".to_string(),
            "--cap-add".to_string(),
            "SYS_ADMIN".to_string(),
            "ubuntu".to_string(),
        ];
        let config = default_config();
        let decision = evaluate_docker_args(&args, &config, "/tmp", None);
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn test_evaluate_network_host() {
        let args = vec![
            "run".to_string(),
            "--network=host".to_string(),
            "ubuntu".to_string(),
        ];
        let config = default_config();
        let decision = evaluate_docker_args(&args, &config, "/tmp", None);
        assert!(matches!(decision, Decision::Deny(_)));
    }
}
