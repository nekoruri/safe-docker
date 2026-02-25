pub mod audit;
pub mod compose;
pub mod config;
pub mod docker_args;
pub mod error;
pub mod hook;
pub mod path_validator;
pub mod policy;
pub mod shell;
pub mod wrapper;

use config::ConfigIssue;
use hook::Decision;

fn main() {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();

    // --check-config サブコマンド
    if args.iter().any(|a| a == "--check-config") {
        std::process::exit(run_check_config(&args));
    }

    // --help / --version (ラッパーモード固有)
    if args.iter().any(|a| a == "--help" || a == "-h") && !is_docker_help_request(&args) {
        print_help();
        return;
    }
    if args.len() == 2 && args[1] == "--version" {
        println!("safe-docker {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    // モード判別:
    // 1. argv[0] が "docker" / "docker-compose" → ラッパーモード（透過）
    // 2. CLI 引数あり → ラッパーモード（明示的）
    // 3. CLI 引数なし → hook モード（stdin JSON）
    let mode = detect_mode(&args);

    match mode {
        RunMode::Wrapper(docker_args) => {
            let config = match config::Config::load() {
                Ok(config) => config,
                Err(e) => {
                    log::warn!("Failed to load config, using defaults: {}", e);
                    config::Config::default()
                }
            };
            std::process::exit(wrapper::run(&docker_args, &config));
        }
        RunMode::Hook => {
            run_hook_mode();
        }
    }
}

/// 実行モード
enum RunMode {
    /// ラッパーモード: docker 引数の配列
    Wrapper(Vec<String>),
    /// hook モード: stdin から JSON を読み取る
    Hook,
}

/// argv[0] と引数からモードを判別する
fn detect_mode(args: &[String]) -> RunMode {
    // argv[0] のファイル名を取得
    let argv0 = args
        .first()
        .and_then(|a| std::path::Path::new(a).file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("");

    // argv[0] が "docker" / "docker-compose" → 透過ラッパーモード
    if argv0 == "docker" {
        // args[1..] をそのまま docker 引数として渡す
        return RunMode::Wrapper(args[1..].to_vec());
    }
    if argv0 == "docker-compose" {
        // "compose" を先頭に挿入して正規化
        let mut docker_args = vec!["compose".to_string()];
        docker_args.extend_from_slice(&args[1..]);
        return RunMode::Wrapper(docker_args);
    }

    // CLI 引数があればラッパーモード（明示的）
    if args.len() > 1 {
        return RunMode::Wrapper(args[1..].to_vec());
    }

    // 引数なし → hook モード
    RunMode::Hook
}

/// docker 自体の --help を要求しているか判定
/// (safe-docker run --help のような場合は docker の help)
fn is_docker_help_request(args: &[String]) -> bool {
    // args[1] が docker サブコマンドや docker 引数の場合
    args.len() > 2
        && args.get(1).is_some_and(|a| {
            !a.starts_with('-')
                || a == "--help"
                || a == "-h"
        })
        && args.iter().skip(2).any(|a| a == "--help" || a == "-h")
}

/// ヘルプメッセージを表示
fn print_help() {
    eprintln!("safe-docker {} - Safe Docker command wrapper", env!("CARGO_PKG_VERSION"));
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  safe-docker [OPTIONS] <docker-args>...     Wrapper mode");
    eprintln!("  safe-docker --check-config [--config PATH] Check configuration");
    eprintln!("  echo '{{...}}' | safe-docker                 Hook mode (Claude Code)");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("  --dry-run       Show decision without executing docker");
    eprintln!("  --verbose       Show detailed decision reasons");
    eprintln!("  --check-config  Validate configuration file");
    eprintln!("  --help, -h      Show this help message");
    eprintln!("  --version       Show version");
    eprintln!();
    eprintln!("ENVIRONMENT:");
    eprintln!("  SAFE_DOCKER_DOCKER_PATH  Path to real docker binary");
    eprintln!("  SAFE_DOCKER_ASK          Non-interactive ask handling (deny/allow)");
    eprintln!("  SAFE_DOCKER_BYPASS       Set to 1 to skip safety checks");
    eprintln!("  SAFE_DOCKER_ACTIVE       Internal: recursion prevention");
    eprintln!();
    eprintln!("EXAMPLES:");
    eprintln!("  safe-docker run -v ~/projects:/app ubuntu");
    eprintln!("  safe-docker compose up");
    eprintln!("  safe-docker --dry-run run --privileged ubuntu");
}

/// hook モードの実行（従来のメインロジック）
fn run_hook_mode() {
    // パニック時は deny (fail-safe)
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        hook::output_deny(&format!(
            "[safe-docker] Internal error (panic). Blocking for safety. Please report this issue: {}",
            info
        ));
    }));

    // stdin から hook 入力を読み取る
    let input = match hook::read_input() {
        Ok(input) => input,
        Err(e) => {
            // 入力エラーは fail-safe (deny)
            // 巨大入力によるバイパスや不正な入力を防ぐ
            let detail = match &e {
                error::SafeDockerError::InputTooLarge(size) => {
                    format!("input too large ({} bytes, max 256KB)", size)
                }
                error::SafeDockerError::Json(_) => "invalid JSON input".to_string(),
                error::SafeDockerError::Io(_) => "failed to read stdin".to_string(),
                _ => format!("{}", e),
            };
            hook::output_deny(&format!("[safe-docker] {}. Blocking for safety.", detail));
            return;
        }
    };

    // Bash ツール以外、またはコマンドが無い場合は即 allow
    let command = match hook::extract_command(&input) {
        Some(cmd) => cmd.to_string(),
        None => return, // exit 0, no output = allow
    };

    // CWD を取得
    let cwd = input
        .cwd
        .clone()
        .or_else(|| {
            std::env::current_dir()
                .ok()
                .and_then(|p| p.to_str().map(String::from))
        })
        .unwrap_or_else(|| ".".to_string());

    // 設定ファイル読み込み
    let config = match config::Config::load() {
        Ok(config) => config,
        Err(e) => {
            log::warn!("Failed to load config, using defaults: {}", e);
            config::Config::default()
        }
    };

    // 監査ログの有効判定
    let audit_enabled = audit::is_enabled(&config.audit);
    let mut collector = if audit_enabled {
        Some(audit::AuditCollector::new())
    } else {
        None
    };

    // コマンドを処理
    let decision = process_command_with_audit(&command, &config, &cwd, collector.as_mut());

    // 結果出力 (★ここで stdout に hook レスポンス)
    hook::output_decision(&decision);

    // 監査ログ出力 (★レスポンス後にファイル I/O)
    if audit_enabled && let Some(ref collector) = collector {
        let (decision_str, reason) = match &decision {
            hook::Decision::Allow => ("allow", None),
            hook::Decision::Deny(r) => ("deny", Some(r.as_str())),
            hook::Decision::Ask(r) => ("ask", Some(r.as_str())),
        };

        let event = audit::build_event(
            &command,
            decision_str,
            reason,
            collector,
            input.session_id.as_deref(),
            &cwd,
        );
        audit::emit(&event, &config.audit);
    }
}

/// --check-config サブコマンドの実行
fn run_check_config(args: &[String]) -> i32 {
    // --config <path> オプションの処理
    let config_path = args
        .windows(2)
        .find(|w| w[0] == "--config")
        .map(|w| std::path::PathBuf::from(&w[1]));

    let (config, config_source) = match &config_path {
        Some(path) => match config::Config::load_from(path) {
            Ok(c) => (c, format!("{}", path.display())),
            Err(e) => {
                eprintln!(
                    "Error: failed to load config from {}: {}",
                    path.display(),
                    e
                );
                return 1;
            }
        },
        None => {
            let default_path = dirs::config_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("~/.config"))
                .join("safe-docker")
                .join("config.toml");
            let source = if default_path.exists() {
                format!("{}", default_path.display())
            } else {
                "(default - no config file found)".to_string()
            };
            match config::Config::load() {
                Ok(c) => (c, source),
                Err(e) => {
                    eprintln!("Error: failed to load config: {}", e);
                    return 1;
                }
            }
        }
    };

    eprintln!("Config source: {}", config_source);
    eprintln!();

    // 現在の設定を表示
    print_config_summary(&config);

    // バリデーション実行
    let issues = config.validate();

    if issues.is_empty() {
        eprintln!("Validation: OK (no issues found)");
        return 0;
    }

    eprintln!("Validation issues:");
    let mut has_errors = false;
    for issue in &issues {
        match issue {
            ConfigIssue::Error(msg) => {
                eprintln!("  ERROR: {}", msg);
                has_errors = true;
            }
            ConfigIssue::Warning(msg) => {
                eprintln!("  WARNING: {}", msg);
            }
        }
    }

    if has_errors { 1 } else { 0 }
}

/// 設定のサマリーを stderr に出力
fn print_config_summary(config: &config::Config) {
    eprintln!("Current configuration:");
    eprintln!(
        "  allowed_paths:        [{}]",
        if config.allowed_paths.is_empty() {
            "(none)".to_string()
        } else {
            config.allowed_paths.join(", ")
        }
    );
    eprintln!(
        "  sensitive_paths:      [{}]",
        config.sensitive_paths.join(", ")
    );
    eprintln!(
        "  blocked_flags:        [{}]",
        config.blocked_flags.join(", ")
    );
    eprintln!(
        "  blocked_capabilities: [{}]",
        config.blocked_capabilities.join(", ")
    );
    eprintln!(
        "  allowed_images:       [{}]",
        if config.allowed_images.is_empty() {
            "(any)".to_string()
        } else {
            config.allowed_images.join(", ")
        }
    );
    eprintln!("  block_docker_socket:  {}", config.block_docker_socket);
    eprintln!("  audit.enabled:        {}", config.audit.enabled);
    if config.audit.enabled {
        eprintln!("  audit.format:         {:?}", config.audit.format);
        eprintln!("  audit.jsonl_path:     {}", config.audit.jsonl_path);
        eprintln!("  audit.otlp_path:      {}", config.audit.otlp_path);
    }
    eprintln!();
}

/// コマンド文字列を解析して最終的な Decision を返す (既存 API 互換)
pub fn process_command(command: &str, config: &config::Config, cwd: &str) -> Decision {
    process_command_with_audit(command, config, cwd, None)
}

/// コマンド文字列を解析して最終的な Decision を返す (監査コレクター付き)
pub fn process_command_with_audit(
    command: &str,
    config: &config::Config,
    cwd: &str,
    mut collector: Option<&mut audit::AuditCollector>,
) -> Decision {
    // シェルコマンドをセグメントに分割
    let segments = shell::split_commands(command);

    let mut all_deny_reasons = Vec::new();
    let mut all_ask_reasons = Vec::new();

    for segment in &segments {
        // シェル間接実行 (eval, bash -c 等) の検出
        if shell::detect_shell_wrappers(segment) {
            all_deny_reasons.push(
                "[safe-docker] Shell wrapper detected: indirect docker execution via eval/sh -c/bash -c is not allowed (run docker commands directly instead)".to_string()
            );
            continue;
        }

        // docker コマンドでないセグメントはスキップ
        if !shell::is_docker_command(segment) {
            continue;
        }

        // docker 引数を抽出
        let args = shell::extract_docker_args(segment);
        if args.is_empty() {
            continue;
        }

        // docker 引数をパース
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let docker_cmd = docker_args::parse_docker_args(&args_ref);

        // 監査コレクターにメタデータを記録
        if let Some(ref mut c) = collector {
            c.record_docker_command(&docker_cmd);
        }

        // ポリシー評価
        match policy::evaluate(&docker_cmd, config, cwd) {
            Decision::Allow => {}
            Decision::Deny(reason) => all_deny_reasons.push(reason),
            Decision::Ask(reason) => all_ask_reasons.push(reason),
        }
    }

    // 集約: deny > ask > allow
    if !all_deny_reasons.is_empty() {
        Decision::Deny(all_deny_reasons.join("\n"))
    } else if !all_ask_reasons.is_empty() {
        Decision::Ask(all_ask_reasons.join("\n"))
    } else {
        Decision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> config::Config {
        config::Config::default()
    }

    fn home_dir() -> String {
        dirs::home_dir().unwrap().to_string_lossy().to_string()
    }

    #[test]
    fn test_non_docker_command() {
        let decision = process_command("ls -la /tmp", &default_config(), "/tmp");
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_docker_no_mounts() {
        let decision = process_command("docker run ubuntu echo hello", &default_config(), "/tmp");
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_docker_allowed_mount() {
        let cmd = format!("docker run -v {}/projects:/app ubuntu", home_dir());
        let decision = process_command(&cmd, &default_config(), "/tmp");
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_docker_denied_mount() {
        let decision =
            process_command("docker run -v /etc:/data ubuntu", &default_config(), "/tmp");
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn test_docker_privileged() {
        let decision = process_command("docker run --privileged ubuntu", &default_config(), "/tmp");
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn test_docker_sensitive_mount() {
        let cmd = format!("docker run -v {}/.ssh:/keys ubuntu", home_dir());
        let decision = process_command(&cmd, &default_config(), "/tmp");
        assert!(matches!(decision, Decision::Ask(_)));
    }

    #[test]
    fn test_piped_command_with_docker() {
        let decision = process_command(
            "echo test | docker run -v /etc:/data ubuntu",
            &default_config(),
            "/tmp",
        );
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn test_chained_command_with_docker() {
        let decision = process_command(
            "cd /tmp && docker run -v /etc:/data ubuntu",
            &default_config(),
            "/tmp",
        );
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn test_docker_mount_equals() {
        let decision = process_command(
            "docker run --mount type=bind,source=/etc,target=/data ubuntu",
            &default_config(),
            "/tmp",
        );
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn test_docker_tilde_mount() {
        let decision = process_command(
            "docker run -v ~/projects:/app ubuntu",
            &default_config(),
            "/tmp",
        );
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_docker_ps() {
        let decision = process_command("docker ps", &default_config(), "/tmp");
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_docker_build() {
        let decision = process_command("docker build -t myapp .", &default_config(), "/tmp");
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_docker_cap_add_sys_admin() {
        let decision = process_command(
            "docker run --cap-add SYS_ADMIN ubuntu",
            &default_config(),
            "/tmp",
        );
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn test_docker_device() {
        let decision = process_command(
            "docker run --device /dev/sda ubuntu",
            &default_config(),
            "/tmp",
        );
        assert!(matches!(decision, Decision::Deny(_)));
    }
}
