use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use crate::config::{Config, NonInteractiveAsk};
use crate::hook::Decision;
use crate::{audit, docker_args, policy};

/// Docker バイナリの検索結果
pub struct DockerResolution {
    /// 発見されたバイナリのパス
    pub path: PathBuf,
    /// 検索ソース（"SAFE_DOCKER_DOCKER_PATH", "wrapper.docker_path", "PATH"）
    pub source: &'static str,
}

/// ラッパーモードのメインエントリポイント
///
/// docker 引数を評価し、Decision に応じてアクションを実行する。
/// - Allow → 本物の docker を exec
/// - Deny → stderr にエラー表示 + exit 1
/// - Ask → 対話的確認（非対話環境では設定に従う）
pub fn run(args: &[String], config: &Config, config_source: &str) -> i32 {
    // 再帰呼び出し防止チェック
    if std::env::var("SAFE_DOCKER_ACTIVE").is_ok_and(|v| v == "1") {
        // 既に safe-docker 経由 → 本物の docker を直接実行
        match find_real_docker_detailed(config) {
            Ok(res) => exec_docker(&res.path, args), // never returns
            Err(tried) => {
                print_docker_not_found(&tried);
                return 1;
            }
        }
    }

    // バイパスモード
    if std::env::var("SAFE_DOCKER_BYPASS").is_ok_and(|v| v == "1") {
        match find_real_docker_detailed(config) {
            Ok(res) => exec_docker(&res.path, args), // never returns
            Err(tried) => {
                print_docker_not_found(&tried);
                return 1;
            }
        }
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

    // verbose: 設定ソースと docker 解決結果を表示
    if verbose {
        eprintln!("[safe-docker] Config: {}", config_source);
        match find_real_docker_detailed(config) {
            Ok(ref res) => {
                eprintln!(
                    "[safe-docker] Docker: {} (via {})",
                    res.path.display(),
                    res.source
                );
            }
            Err(ref tried) => {
                eprintln!("[safe-docker] Docker: not found");
                for t in tried {
                    eprintln!("[safe-docker]   {}", t);
                }
            }
        }
    }

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

        let event = audit::build_event(&audit::AuditContext {
            command: &command_str,
            decision: decision_str,
            reason,
            collector,
            session_id: None,
            cwd: &cwd,
            mode: "wrapper",
            config_source: Some(config_source),
        });
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
            match find_real_docker_detailed(config) {
                Ok(res) => exec_docker(&res.path, &docker_args), // never returns
                Err(tried) => {
                    print_docker_not_found(&tried);
                    1
                }
            }
        }
        Decision::Deny(reason) => {
            eprintln!("{}", reason);
            if verbose {
                for tip in generate_tips(&reason) {
                    eprintln!("  Tip: {}", tip);
                }
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
                match find_real_docker_detailed(config) {
                    Ok(res) => exec_docker(&res.path, docker_args), // never returns
                    Err(tried) => {
                        print_docker_not_found(&tried);
                        1
                    }
                }
            }
            NonInteractiveAsk::Deny => {
                eprintln!(
                    "[safe-docker] Non-interactive: blocked (set SAFE_DOCKER_ASK=allow to override)"
                );
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
                match find_real_docker_detailed(config) {
                    Ok(res) => exec_docker(&res.path, docker_args), // never returns
                    Err(tried) => {
                        print_docker_not_found(&tried);
                        1
                    }
                }
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

/// 本物の docker バイナリを検索する（簡易版）
///
/// 優先順位:
/// 1. 環境変数 SAFE_DOCKER_DOCKER_PATH
/// 2. 設定ファイルの wrapper.docker_path
/// 3. PATH から自動検索（自分自身を除外）
pub fn find_real_docker(config: &Config) -> Option<PathBuf> {
    find_real_docker_detailed(config).ok().map(|r| r.path)
}

/// 本物の docker バイナリを検索する（詳細情報付き）
///
/// 成功時は DockerResolution（パスと検索ソース）を返す。
/// 失敗時は試行した検索手順のリストを返す。
pub fn find_real_docker_detailed(config: &Config) -> Result<DockerResolution, Vec<String>> {
    let mut tried = Vec::new();

    // 1. 環境変数
    if let Ok(path) = std::env::var("SAFE_DOCKER_DOCKER_PATH")
        && !path.is_empty()
    {
        let p = PathBuf::from(&path);
        if p.exists() {
            return Ok(DockerResolution {
                path: p,
                source: "SAFE_DOCKER_DOCKER_PATH",
            });
        }
        tried.push(format!("SAFE_DOCKER_DOCKER_PATH={} (file not found)", path));
    }

    // 2. 設定ファイル
    if !config.wrapper.docker_path.is_empty() {
        let p = PathBuf::from(&config.wrapper.docker_path);
        if p.exists() {
            return Ok(DockerResolution {
                path: p,
                source: "wrapper.docker_path",
            });
        }
        tried.push(format!(
            "wrapper.docker_path={} (file not found)",
            config.wrapper.docker_path
        ));
    }

    // 3. PATH 自動検索（自分自身を除外）
    if let Some(p) = find_docker_in_path() {
        return Ok(DockerResolution {
            path: p,
            source: "PATH",
        });
    }
    tried.push("PATH search (no docker binary found)".to_string());

    Err(tried)
}

/// Docker バイナリが見つからなかった場合の詳細エラーを表示
fn print_docker_not_found(tried: &[String]) {
    eprintln!("[safe-docker] Error: could not find the real docker binary");
    for t in tried {
        eprintln!("  Tried: {}", t);
    }
    eprintln!(
        "  Tip: Set --docker-path <PATH> or SAFE_DOCKER_DOCKER_PATH to specify the docker binary"
    );
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

/// Deny/Ask 理由から具体的な対処法を生成する
fn generate_tips(reason: &str) -> Vec<String> {
    let mut tips = Vec::new();

    // パス関連
    if reason.contains("outside $HOME") {
        tips.push(
            "To allow this path, add it to allowed_paths in ~/.config/safe-docker/config.toml"
                .to_string(),
        );
    }
    if reason.contains("Docker socket mount is blocked") {
        tips.push(
            "To allow Docker socket access, set block_docker_socket = false in config.toml"
                .to_string(),
        );
    }
    if reason.contains("sensitive path") || reason.contains("credentials or keys") {
        tips.push(
            "Sensitive paths trigger a confirmation prompt. Consider using read-only mounts (:ro)"
                .to_string(),
        );
    }

    // 危険フラグ関連
    if reason.contains("--privileged") {
        tips.push(
            "Instead of --privileged, grant only the specific capabilities needed with --cap-add"
                .to_string(),
        );
    }
    if reason.contains("--cap-add") {
        tips.push(
            "To allow this capability, remove it from blocked_capabilities in config.toml"
                .to_string(),
        );
    }
    if reason.contains("--security-opt") {
        tips.push("Avoid disabling security profiles in production environments".to_string());
    }
    if reason.contains("--pid=host")
        || reason.contains("--network=host")
        || reason.contains("--userns=host")
        || reason.contains("--ipc=host")
        || reason.contains("--cgroupns=host")
        || reason.contains("--uts=host")
    {
        tips.push(
            "Host namespace sharing is blocked by default. Remove the flag from blocked_flags in config.toml to allow"
                .to_string(),
        );
    }
    if reason.contains("--device") {
        tips.push(
            "Direct device access is blocked for security. Consider using a volume mount instead"
                .to_string(),
        );
    }
    if reason.contains("--network=container:")
        || reason.contains("--pid=container:")
        || reason.contains("--ipc=container:")
    {
        tips.push(
            "Container namespace sharing allows cross-container access and is blocked by default"
                .to_string(),
        );
    }
    if reason.contains("bind-propagation=") {
        tips.push(
            "shared/rshared propagation allows mount changes to reach the host. Use private (default) instead"
                .to_string(),
        );
    }
    if reason.contains("--sysctl") || reason.contains("sysctl") {
        tips.push(
            "kernel.* sysctls are blocked because they affect the host kernel directly. Use container-safe net.* sysctls only"
                .to_string(),
        );
    }
    if reason.contains("metadata endpoint") || reason.contains("169.254.169.254") {
        tips.push(
            "The cloud metadata endpoint (169.254.169.254) is commonly targeted in SSRF attacks to steal credentials"
                .to_string(),
        );
    }
    if reason.contains("label=disable") || reason.contains("label:disable") {
        tips.push(
            "Disabling SELinux labels (CIS 5.2) removes mandatory access control protection"
                .to_string(),
        );
    }
    if reason.contains("--build-arg") && reason.contains("secret") {
        tips.push(
            "Build args are stored in image layers and visible via 'docker history'. Use BuildKit --secret for sensitive values"
                .to_string(),
        );
    }
    if reason.contains("Compose env_file") {
        tips.push(
            "Compose env_file reads host files into container environment. Ensure the file is within $HOME or add its path to allowed_paths"
                .to_string(),
        );
    }
    if reason.contains("Compose include") {
        tips.push(
            "Compose include references external files that may contain dangerous settings. Verify the included file is safe"
                .to_string(),
        );
    }

    // Compose 関連
    if reason.contains("Compose:") {
        tips.push(
            "Fix the flagged settings in your compose file, or adjust config.toml".to_string(),
        );
    }
    if reason.contains("No compose file found") {
        tips.push(
            "Create compose.yml or docker-compose.yml, or specify the file with -f".to_string(),
        );
    }

    // イメージ関連
    if reason.contains("not in allowed_images") {
        tips.push(
            "Add the image to allowed_images in config.toml, or clear the list to allow any image"
                .to_string(),
        );
    }

    // フォールバック: 何もマッチしなかった場合
    if tips.is_empty() {
        tips.push(
            "Check ~/.config/safe-docker/config.toml to adjust the security policy".to_string(),
        );
    }

    tips
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
    use crate::test_utils::{TempEnvVar, env_lock};

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
        let lock = env_lock();
        let config = default_config();
        // /usr/bin/docker が存在する場合のテスト
        if Path::new("/usr/bin/docker").exists() {
            let _env = TempEnvVar::set(&lock, "SAFE_DOCKER_DOCKER_PATH", "/usr/bin/docker");
            let result = find_real_docker(&config);
            assert_eq!(result, Some(PathBuf::from("/usr/bin/docker")));
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

    // --- find_real_docker_detailed テスト ---

    #[test]
    fn test_find_real_docker_detailed_env_var_source() {
        let lock = env_lock();
        let _env = TempEnvVar::set(&lock, "SAFE_DOCKER_DOCKER_PATH", "/bin/echo");

        let config = default_config();
        let result = find_real_docker_detailed(&config);
        assert!(result.is_ok());
        let res = result.unwrap();
        assert_eq!(res.path, PathBuf::from("/bin/echo"));
        assert_eq!(res.source, "SAFE_DOCKER_DOCKER_PATH");
    }

    #[test]
    fn test_find_real_docker_detailed_config_source() {
        let lock = env_lock();
        let _env = TempEnvVar::remove(&lock, "SAFE_DOCKER_DOCKER_PATH");

        let mut config = default_config();
        config.wrapper.docker_path = "/bin/echo".to_string();
        let result = find_real_docker_detailed(&config);
        assert!(result.is_ok());
        let res = result.unwrap();
        assert_eq!(res.path, PathBuf::from("/bin/echo"));
        assert_eq!(res.source, "wrapper.docker_path");
    }

    #[test]
    fn test_find_real_docker_detailed_not_found() {
        let lock = env_lock();
        let _env = TempEnvVar::set(&lock, "SAFE_DOCKER_DOCKER_PATH", "/nonexistent/docker_abc");

        let mut config = default_config();
        config.wrapper.docker_path = "/nonexistent/docker_xyz".to_string();
        // PATH にも docker がない状態にするのは困難なので、tried の内容をチェック
        let result = find_real_docker_detailed(&config);
        if let Err(tried) = result {
            assert!(
                tried
                    .iter()
                    .any(|t| t.contains("SAFE_DOCKER_DOCKER_PATH=/nonexistent/docker_abc")),
                "tried should contain env var: {:?}",
                tried
            );
            assert!(
                tried
                    .iter()
                    .any(|t| t.contains("wrapper.docker_path=/nonexistent/docker_xyz")),
                "tried should contain config path: {:?}",
                tried
            );
        }
        // PATH に docker がある場合は Ok になるので、そのケースはスキップ
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

    // --- generate_tips テスト ---

    #[test]
    fn test_tips_outside_home() {
        let tips = generate_tips("[safe-docker] Path is outside $HOME: /etc (resolved: /etc)");
        assert!(tips.iter().any(|t| t.contains("allowed_paths")));
    }

    #[test]
    fn test_tips_docker_socket() {
        let tips =
            generate_tips("[safe-docker] Docker socket mount is blocked: /var/run/docker.sock");
        assert!(tips.iter().any(|t| t.contains("block_docker_socket")));
    }

    #[test]
    fn test_tips_sensitive_path() {
        let tips =
            generate_tips("Mounting sensitive path ~/.ssh which may contain credentials or keys");
        assert!(tips.iter().any(|t| t.contains("read-only")));
    }

    #[test]
    fn test_tips_privileged() {
        let tips = generate_tips("[safe-docker] --privileged is not allowed");
        assert!(tips.iter().any(|t| t.contains("--cap-add")));
    }

    #[test]
    fn test_tips_cap_add() {
        let tips = generate_tips("[safe-docker] --cap-add=SYS_ADMIN is blocked");
        assert!(tips.iter().any(|t| t.contains("blocked_capabilities")));
    }

    #[test]
    fn test_tips_network_host() {
        let tips = generate_tips("[safe-docker] --network=host is not allowed");
        assert!(tips.iter().any(|t| t.contains("blocked_flags")));
    }

    #[test]
    fn test_tips_device() {
        let tips = generate_tips("[safe-docker] --device=/dev/sda is not allowed");
        assert!(tips.iter().any(|t| t.contains("volume mount")));
    }

    #[test]
    fn test_tips_compose() {
        let tips = generate_tips("[safe-docker] Compose: 'privileged: true' is not allowed");
        assert!(tips.iter().any(|t| t.contains("compose file")));
    }

    #[test]
    fn test_tips_compose_not_found() {
        let tips = generate_tips("[safe-docker] No compose file found");
        assert!(tips.iter().any(|t| t.contains("compose.yml")));
    }

    #[test]
    fn test_tips_image_not_allowed() {
        let tips = generate_tips("Image 'nginx' is not in allowed_images");
        assert!(tips.iter().any(|t| t.contains("allowed_images")));
    }

    #[test]
    fn test_tips_security_opt() {
        let tips = generate_tips(
            "[safe-docker] --security-opt apparmor=unconfined disables a security profile",
        );
        assert!(tips.iter().any(|t| t.contains("security profiles")));
    }

    #[test]
    fn test_tips_unknown_reason_fallback() {
        let tips = generate_tips("some unknown error reason");
        assert_eq!(tips.len(), 1);
        assert!(tips[0].contains("config.toml"));
    }

    #[test]
    fn test_tips_multiple_issues() {
        // Multiple issues の場合、複数の Tip が返る
        let reason = "[safe-docker] Multiple issues found:\n  - --privileged is not allowed\n  - Path is outside $HOME: /etc";
        let tips = generate_tips(reason);
        assert!(tips.len() >= 2, "Expected multiple tips, got: {:?}", tips);
        assert!(tips.iter().any(|t| t.contains("--cap-add")));
        assert!(tips.iter().any(|t| t.contains("allowed_paths")));
    }
}
