use crate::config::Config;
use crate::docker_args::{DangerousFlag, DockerCommand, DockerSubcommand};
use crate::hook::Decision;
use crate::path_validator::{self, PathVerdict};

/// 危険な --security-opt 値かどうか判定
fn is_dangerous_security_opt(opt: &str) -> bool {
    // = 区切りと : 区切りの両方に対応
    opt.contains("apparmor=unconfined")
        || opt.contains("apparmor:unconfined")
        || opt.contains("seccomp=unconfined")
        || opt.contains("seccomp:unconfined")
        || opt.contains("systempaths=unconfined")
        || opt.contains("systempaths:unconfined")
        || opt.contains("no-new-privileges=false")
        || opt.contains("no-new-privileges:false")
}

/// Docker コマンドに対してポリシーを適用し、最終的な Decision を返す
pub fn evaluate(cmd: &DockerCommand, config: &Config, cwd: &str) -> Decision {
    let mut deny_reasons = Vec::new();
    let mut ask_reasons = Vec::new();

    // 1. 危険フラグのチェック
    for flag in &cmd.dangerous_flags {
        match flag {
            DangerousFlag::Privileged => {
                deny_reasons.push("--privileged flag is not allowed".to_string());
            }
            DangerousFlag::CapAdd(cap) => {
                if config.is_capability_blocked(cap) {
                    deny_reasons.push(format!("--cap-add={} is not allowed", cap));
                }
            }
            DangerousFlag::SecurityOpt(opt) => {
                if is_dangerous_security_opt(opt) {
                    deny_reasons.push(format!("--security-opt {} is not allowed", opt));
                }
            }
            DangerousFlag::PidHost => {
                deny_reasons.push("--pid=host is not allowed".to_string());
            }
            DangerousFlag::NetworkHost => {
                deny_reasons.push("--network=host is not allowed".to_string());
            }
            DangerousFlag::Device(dev) => {
                deny_reasons.push(format!("--device={} is not allowed", dev));
            }
            DangerousFlag::VolumesFrom(src) => {
                ask_reasons.push(format!(
                    "--volumes-from={} may inherit dangerous mounts from another container",
                    src
                ));
            }
            DangerousFlag::UsernsHost => {
                deny_reasons.push("--userns=host is not allowed".to_string());
            }
            DangerousFlag::CgroupnsHost => {
                deny_reasons.push("--cgroupns=host is not allowed".to_string());
            }
            DangerousFlag::IpcHost => {
                deny_reasons.push("--ipc=host is not allowed".to_string());
            }
        }
    }

    // 2. compose コマンドの場合、compose ファイルを解析
    let mut all_mounts = cmd.bind_mounts.clone();
    let mut all_flags: Vec<DangerousFlag> = Vec::new();
    if matches!(
        cmd.subcommand,
        DockerSubcommand::ComposeUp
            | DockerSubcommand::ComposeRun
            | DockerSubcommand::ComposeCreate
    ) {
        match resolve_compose_analysis(cmd, cwd) {
            Ok(analysis) => {
                all_mounts.extend(analysis.bind_mounts);
                all_flags.extend(analysis.dangerous_flags);
            }
            Err(reason) => {
                // compose ファイルのパースエラーは deny (fail-safe)
                deny_reasons.push(reason);
            }
        }
    }

    // compose ファイルから検出された危険フラグをチェック
    for flag in &all_flags {
        match flag {
            DangerousFlag::Privileged => {
                deny_reasons.push("Compose: privileged is not allowed".to_string());
            }
            DangerousFlag::CapAdd(cap) => {
                if config.is_capability_blocked(cap) {
                    deny_reasons.push(format!("Compose: cap_add {} is not allowed", cap));
                }
            }
            DangerousFlag::SecurityOpt(opt) => {
                if is_dangerous_security_opt(opt) {
                    deny_reasons.push(format!("Compose: security_opt {} is not allowed", opt));
                }
            }
            DangerousFlag::PidHost => {
                deny_reasons.push("Compose: pid host is not allowed".to_string());
            }
            DangerousFlag::NetworkHost => {
                deny_reasons.push("Compose: network_mode host is not allowed".to_string());
            }
            DangerousFlag::Device(dev) => {
                deny_reasons.push(format!("Compose: device {} is not allowed", dev));
            }
            DangerousFlag::UsernsHost => {
                deny_reasons.push("Compose: userns_mode host is not allowed".to_string());
            }
            DangerousFlag::IpcHost => {
                deny_reasons.push("Compose: ipc host is not allowed".to_string());
            }
            _ => {}
        }
    }

    // 3. バインドマウントのパス検証
    for mount in &all_mounts {
        match path_validator::validate_path(&mount.host_path, config) {
            PathVerdict::Allowed => {}
            PathVerdict::Sensitive(reason) => {
                ask_reasons.push(reason);
            }
            PathVerdict::Denied(reason) => {
                deny_reasons.push(reason);
            }
            PathVerdict::Unresolvable(reason) => {
                ask_reasons.push(reason);
            }
        }
    }

    // 4. ホストパスの検証 (docker cp, docker build)
    for host_path in &cmd.host_paths {
        match path_validator::validate_path(host_path, config) {
            PathVerdict::Allowed => {}
            PathVerdict::Sensitive(reason) => {
                ask_reasons.push(reason);
            }
            PathVerdict::Denied(reason) => {
                deny_reasons.push(reason);
            }
            PathVerdict::Unresolvable(reason) => {
                ask_reasons.push(reason);
            }
        }
    }

    // 5. イメージホワイトリスト
    if !config.allowed_images.is_empty()
        && let Some(image) = &cmd.image
    {
        let image_name = image.split(':').next().unwrap_or(image);
        if !config
            .allowed_images
            .iter()
            .any(|allowed| image_name == allowed)
        {
            ask_reasons.push(format!("Image '{}' is not in the allowed list", image));
        }
    }

    // 6. 結果集約: deny が一つでもあれば deny、ask があれば ask、それ以外は allow
    if !deny_reasons.is_empty() {
        Decision::Deny(format_reasons(&deny_reasons))
    } else if !ask_reasons.is_empty() {
        Decision::Ask(format_reasons(&ask_reasons))
    } else {
        Decision::Allow
    }
}

/// compose ファイルを解析してマウントと危険設定を返す
fn resolve_compose_analysis(
    cmd: &DockerCommand,
    cwd: &str,
) -> std::result::Result<crate::compose::ComposeAnalysis, String> {
    let compose_path = crate::compose::find_compose_file(cmd.compose_file.as_deref(), cwd);

    match compose_path {
        Some(path) => {
            if !path.exists() {
                return Err(format!("Compose file not found: {}", path.display()));
            }
            crate::compose::analyze_compose(&path).map_err(|e| e.to_string())
        }
        None => {
            // compose ファイルが見つからない場合は deny
            Err("No compose file found in current directory".to_string())
        }
    }
}

/// 理由リストを整形して一つの文字列にする
fn format_reasons(reasons: &[String]) -> String {
    if reasons.len() == 1 {
        format!("[safe-docker] {}", reasons[0])
    } else {
        let items: Vec<String> = reasons.iter().map(|r| format!("  - {}", r)).collect();
        format!("[safe-docker] Multiple issues found:\n{}", items.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docker_args::{BindMount, MountSource};

    fn home_path(suffix: &str) -> String {
        let home = dirs::home_dir().unwrap().to_string_lossy().to_string();
        format!("{}/{}", home, suffix)
    }

    #[test]
    fn test_evaluate_allowed() {
        let config = Config::default();
        let cmd = DockerCommand {
            subcommand: DockerSubcommand::Run,
            bind_mounts: vec![BindMount {
                host_path: home_path("projects/app"),
                container_path: "/app".to_string(),
                source: MountSource::VolumeFlag,
                read_only: false,
            }],
            dangerous_flags: vec![],
            compose_file: None,
            image: Some("ubuntu".to_string()),
            host_paths: vec![],
        };
        assert_eq!(evaluate(&cmd, &config, "/tmp"), Decision::Allow);
    }

    #[test]
    fn test_evaluate_denied_outside_home() {
        let config = Config::default();
        let cmd = DockerCommand {
            subcommand: DockerSubcommand::Run,
            bind_mounts: vec![BindMount {
                host_path: "/etc".to_string(),
                container_path: "/data".to_string(),
                source: MountSource::VolumeFlag,
                read_only: false,
            }],
            dangerous_flags: vec![],
            compose_file: None,
            image: Some("ubuntu".to_string()),
            host_paths: vec![],
        };
        let decision = evaluate(&cmd, &config, "/tmp");
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn test_evaluate_privileged() {
        let config = Config::default();
        let cmd = DockerCommand {
            subcommand: DockerSubcommand::Run,
            bind_mounts: vec![],
            dangerous_flags: vec![DangerousFlag::Privileged],
            compose_file: None,
            image: Some("ubuntu".to_string()),
            host_paths: vec![],
        };
        let decision = evaluate(&cmd, &config, "/tmp");
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn test_evaluate_sensitive_path() {
        let config = Config::default();
        let cmd = DockerCommand {
            subcommand: DockerSubcommand::Run,
            bind_mounts: vec![BindMount {
                host_path: home_path(".ssh"),
                container_path: "/keys".to_string(),
                source: MountSource::VolumeFlag,
                read_only: false,
            }],
            dangerous_flags: vec![],
            compose_file: None,
            image: Some("ubuntu".to_string()),
            host_paths: vec![],
        };
        let decision = evaluate(&cmd, &config, "/tmp");
        assert!(matches!(decision, Decision::Ask(_)));
    }

    #[test]
    fn test_evaluate_dangerous_cap() {
        let config = Config::default();
        let cmd = DockerCommand {
            subcommand: DockerSubcommand::Run,
            bind_mounts: vec![],
            dangerous_flags: vec![DangerousFlag::CapAdd("SYS_ADMIN".to_string())],
            compose_file: None,
            image: Some("ubuntu".to_string()),
            host_paths: vec![],
        };
        let decision = evaluate(&cmd, &config, "/tmp");
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn test_evaluate_multiple_issues() {
        let config = Config::default();
        let cmd = DockerCommand {
            subcommand: DockerSubcommand::Run,
            bind_mounts: vec![BindMount {
                host_path: "/etc".to_string(),
                container_path: "/data".to_string(),
                source: MountSource::VolumeFlag,
                read_only: false,
            }],
            dangerous_flags: vec![DangerousFlag::Privileged],
            compose_file: None,
            image: Some("ubuntu".to_string()),
            host_paths: vec![],
        };
        let decision = evaluate(&cmd, &config, "/tmp");
        match decision {
            Decision::Deny(reason) => {
                assert!(reason.contains("Multiple issues"));
            }
            _ => panic!("Expected Deny"),
        }
    }

    #[test]
    fn test_evaluate_no_mounts_no_flags() {
        let config = Config::default();
        let cmd = DockerCommand {
            subcommand: DockerSubcommand::Run,
            bind_mounts: vec![],
            dangerous_flags: vec![],
            compose_file: None,
            image: Some("ubuntu".to_string()),
            host_paths: vec![],
        };
        assert_eq!(evaluate(&cmd, &config, "/tmp"), Decision::Allow);
    }

    #[test]
    fn test_format_reasons_single() {
        let result = format_reasons(&["test reason".to_string()]);
        assert_eq!(result, "[safe-docker] test reason");
    }

    #[test]
    fn test_format_reasons_multiple() {
        let result = format_reasons(&["reason 1".to_string(), "reason 2".to_string()]);
        assert!(result.contains("Multiple issues"));
        assert!(result.contains("reason 1"));
        assert!(result.contains("reason 2"));
    }

    // --- ポリシーバリエーションテスト ---

    #[test]
    fn test_evaluate_allowed_images_not_in_list() {
        let mut config = Config::default();
        config.allowed_images = vec!["ubuntu".to_string(), "alpine".to_string()];
        let cmd = DockerCommand {
            subcommand: DockerSubcommand::Run,
            bind_mounts: vec![],
            dangerous_flags: vec![],
            compose_file: None,
            image: Some("nginx".to_string()),
            host_paths: vec![],
        };
        let decision = evaluate(&cmd, &config, "/tmp");
        assert!(
            matches!(decision, Decision::Ask(_)),
            "Image not in allowed list should ask: {:?}",
            decision
        );
    }

    #[test]
    fn test_evaluate_allowed_images_in_list() {
        let mut config = Config::default();
        config.allowed_images = vec!["ubuntu".to_string(), "alpine".to_string()];
        let cmd = DockerCommand {
            subcommand: DockerSubcommand::Run,
            bind_mounts: vec![],
            dangerous_flags: vec![],
            compose_file: None,
            image: Some("ubuntu".to_string()),
            host_paths: vec![],
        };
        let decision = evaluate(&cmd, &config, "/tmp");
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_evaluate_allowed_images_with_tag() {
        let mut config = Config::default();
        config.allowed_images = vec!["ubuntu".to_string()];
        let cmd = DockerCommand {
            subcommand: DockerSubcommand::Run,
            bind_mounts: vec![],
            dangerous_flags: vec![],
            compose_file: None,
            image: Some("ubuntu:22.04".to_string()),
            host_paths: vec![],
        };
        let decision = evaluate(&cmd, &config, "/tmp");
        assert_eq!(
            decision,
            Decision::Allow,
            "Image with tag should match allowed list"
        );
    }

    #[test]
    fn test_evaluate_security_opt_apparmor_unconfined() {
        let config = Config::default();
        let cmd = DockerCommand {
            subcommand: DockerSubcommand::Run,
            bind_mounts: vec![],
            dangerous_flags: vec![DangerousFlag::SecurityOpt(
                "apparmor=unconfined".to_string(),
            )],
            compose_file: None,
            image: Some("ubuntu".to_string()),
            host_paths: vec![],
        };
        let decision = evaluate(&cmd, &config, "/tmp");
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn test_evaluate_security_opt_seccomp_unconfined() {
        let config = Config::default();
        let cmd = DockerCommand {
            subcommand: DockerSubcommand::Run,
            bind_mounts: vec![],
            dangerous_flags: vec![DangerousFlag::SecurityOpt("seccomp=unconfined".to_string())],
            compose_file: None,
            image: Some("ubuntu".to_string()),
            host_paths: vec![],
        };
        let decision = evaluate(&cmd, &config, "/tmp");
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn test_evaluate_security_opt_apparmor_colon() {
        let config = Config::default();
        let cmd = DockerCommand {
            subcommand: DockerSubcommand::Run,
            bind_mounts: vec![],
            dangerous_flags: vec![DangerousFlag::SecurityOpt(
                "apparmor:unconfined".to_string(),
            )],
            compose_file: None,
            image: Some("ubuntu".to_string()),
            host_paths: vec![],
        };
        let decision = evaluate(&cmd, &config, "/tmp");
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn test_evaluate_security_opt_no_new_privileges() {
        let config = Config::default();
        let cmd = DockerCommand {
            subcommand: DockerSubcommand::Run,
            bind_mounts: vec![],
            dangerous_flags: vec![DangerousFlag::SecurityOpt(
                "no-new-privileges=false".to_string(),
            )],
            compose_file: None,
            image: Some("ubuntu".to_string()),
            host_paths: vec![],
        };
        let decision = evaluate(&cmd, &config, "/tmp");
        // no-new-privileges=false はセキュリティ制限の無効化なので deny
        assert!(
            matches!(decision, Decision::Deny(_)),
            "no-new-privileges=false should be denied"
        );
    }

    #[test]
    fn test_evaluate_security_opt_systempaths_unconfined() {
        let config = Config::default();
        let cmd = DockerCommand {
            subcommand: DockerSubcommand::Run,
            bind_mounts: vec![],
            dangerous_flags: vec![DangerousFlag::SecurityOpt(
                "systempaths=unconfined".to_string(),
            )],
            compose_file: None,
            image: Some("ubuntu".to_string()),
            host_paths: vec![],
        };
        let decision = evaluate(&cmd, &config, "/tmp");
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn test_evaluate_security_opt_systempaths_colon() {
        let config = Config::default();
        let cmd = DockerCommand {
            subcommand: DockerSubcommand::Run,
            bind_mounts: vec![],
            dangerous_flags: vec![DangerousFlag::SecurityOpt(
                "systempaths:unconfined".to_string(),
            )],
            compose_file: None,
            image: Some("ubuntu".to_string()),
            host_paths: vec![],
        };
        let decision = evaluate(&cmd, &config, "/tmp");
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn test_evaluate_security_opt_no_new_privileges_colon_false() {
        let config = Config::default();
        let cmd = DockerCommand {
            subcommand: DockerSubcommand::Run,
            bind_mounts: vec![],
            dangerous_flags: vec![DangerousFlag::SecurityOpt(
                "no-new-privileges:false".to_string(),
            )],
            compose_file: None,
            image: Some("ubuntu".to_string()),
            host_paths: vec![],
        };
        let decision = evaluate(&cmd, &config, "/tmp");
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn test_evaluate_security_opt_no_new_privileges_true_allows() {
        let config = Config::default();
        let cmd = DockerCommand {
            subcommand: DockerSubcommand::Run,
            bind_mounts: vec![],
            dangerous_flags: vec![DangerousFlag::SecurityOpt("no-new-privileges".to_string())],
            compose_file: None,
            image: Some("ubuntu".to_string()),
            host_paths: vec![],
        };
        let decision = evaluate(&cmd, &config, "/tmp");
        assert_eq!(
            decision,
            Decision::Allow,
            "no-new-privileges (without =false) should be allowed"
        );
    }

    #[test]
    fn test_evaluate_network_host() {
        let config = Config::default();
        let cmd = DockerCommand {
            subcommand: DockerSubcommand::Run,
            bind_mounts: vec![],
            dangerous_flags: vec![DangerousFlag::NetworkHost],
            compose_file: None,
            image: Some("ubuntu".to_string()),
            host_paths: vec![],
        };
        let decision = evaluate(&cmd, &config, "/tmp");
        assert!(matches!(decision, Decision::Deny(_)));
    }

    #[test]
    fn test_evaluate_compose_no_file() {
        let config = Config::default();
        let dir = tempfile::tempdir().unwrap();
        let cmd = DockerCommand {
            subcommand: DockerSubcommand::ComposeUp,
            bind_mounts: vec![],
            dangerous_flags: vec![],
            compose_file: None,
            image: None,
            host_paths: vec![],
        };
        let decision = evaluate(&cmd, &config, dir.path().to_str().unwrap());
        assert!(
            matches!(decision, Decision::Deny(_)),
            "compose without file should deny: {:?}",
            decision
        );
    }

    #[test]
    fn test_evaluate_compose_parse_error() {
        let config = Config::default();
        let dir = tempfile::tempdir().unwrap();
        // YAML パースエラーになる文字列
        std::fs::write(dir.path().join("compose.yml"), ":\n  - :\n  a: [b\n").unwrap();
        let cmd = DockerCommand {
            subcommand: DockerSubcommand::ComposeUp,
            bind_mounts: vec![],
            dangerous_flags: vec![],
            compose_file: None,
            image: None,
            host_paths: vec![],
        };
        let decision = evaluate(&cmd, &config, dir.path().to_str().unwrap());
        assert!(
            matches!(decision, Decision::Deny(_)),
            "compose parse error should deny: {:?}",
            decision
        );
    }

    #[test]
    fn test_evaluate_deny_and_ask_mixed() {
        let config = Config::default();
        let cmd = DockerCommand {
            subcommand: DockerSubcommand::Run,
            bind_mounts: vec![
                BindMount {
                    host_path: "/etc".to_string(),
                    container_path: "/data".to_string(),
                    source: MountSource::VolumeFlag,
                    read_only: false,
                },
                BindMount {
                    host_path: home_path(".ssh"),
                    container_path: "/keys".to_string(),
                    source: MountSource::VolumeFlag,
                    read_only: false,
                },
            ],
            dangerous_flags: vec![],
            compose_file: None,
            image: Some("ubuntu".to_string()),
            host_paths: vec![],
        };
        let decision = evaluate(&cmd, &config, "/tmp");
        // deny (/etc) が ask (.ssh) より優先
        assert!(
            matches!(decision, Decision::Deny(_)),
            "deny should take priority over ask: {:?}",
            decision
        );
    }

    #[test]
    fn test_evaluate_compose_exec_no_file_analysis() {
        let config = Config::default();
        let dir = tempfile::tempdir().unwrap();
        let cmd = DockerCommand {
            subcommand: DockerSubcommand::ComposeExec,
            bind_mounts: vec![],
            dangerous_flags: vec![],
            compose_file: None,
            image: None,
            host_paths: vec![],
        };
        // ComposeExec は compose ファイル解析対象外
        let decision = evaluate(&cmd, &config, dir.path().to_str().unwrap());
        assert_eq!(
            decision,
            Decision::Allow,
            "compose exec should not analyze compose file"
        );
    }

    #[test]
    fn test_evaluate_allowed_paths_tmp() {
        let mut config = Config::default();
        config.allowed_paths = vec!["/tmp".to_string()];
        let cmd = DockerCommand {
            subcommand: DockerSubcommand::Run,
            bind_mounts: vec![BindMount {
                host_path: "/tmp/docker-data".to_string(),
                container_path: "/data".to_string(),
                source: MountSource::VolumeFlag,
                read_only: false,
            }],
            dangerous_flags: vec![],
            compose_file: None,
            image: Some("ubuntu".to_string()),
            host_paths: vec![],
        };
        let decision = evaluate(&cmd, &config, "/tmp");
        assert_eq!(
            decision,
            Decision::Allow,
            "/tmp should be allowed when in allowed_paths"
        );
    }
}
