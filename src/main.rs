pub mod compose;
pub mod config;
pub mod docker_args;
pub mod error;
pub mod hook;
pub mod path_validator;
pub mod policy;
pub mod shell;

use hook::Decision;

fn main() {
    env_logger::init();

    // パニック時は deny (fail-safe)
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        hook::output_deny(&format!(
            "[safe-docker] Internal error (panic). Blocking for safety: {}",
            info
        ));
    }));

    // stdin から hook 入力を読み取る
    let input = match hook::read_input() {
        Ok(input) => input,
        Err(e) => {
            // 入力エラーは fail-safe (deny)
            // 巨大入力によるバイパスや不正な入力を防ぐ
            hook::output_deny(&format!(
                "[safe-docker] Failed to read input: {}. Blocking for safety.",
                e
            ));
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

    // コマンドを処理
    let decision = process_command(&command, &config, &cwd);

    // 結果出力
    hook::output_decision(&decision);
}

/// コマンド文字列を解析して最終的な Decision を返す
pub fn process_command(command: &str, config: &config::Config, cwd: &str) -> Decision {
    // シェルコマンドをセグメントに分割
    let segments = shell::split_commands(command);

    let mut all_deny_reasons = Vec::new();
    let mut all_ask_reasons = Vec::new();

    for segment in &segments {
        // シェル間接実行 (eval, bash -c 等) の検出
        if shell::detect_shell_wrappers(segment) {
            all_deny_reasons.push(
                "[safe-docker] Shell wrapper detected: indirect docker execution via eval/sh -c/bash -c is not allowed for security reasons".to_string()
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
        let decision =
            process_command("docker run ubuntu echo hello", &default_config(), "/tmp");
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
        let decision = process_command(
            "docker run -v /etc:/data ubuntu",
            &default_config(),
            "/tmp",
        );
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn test_docker_privileged() {
        let decision = process_command(
            "docker run --privileged ubuntu",
            &default_config(),
            "/tmp",
        );
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
        let decision =
            process_command("docker build -t myapp .", &default_config(), "/tmp");
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
