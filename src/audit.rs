use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::{AuditConfig, AuditFormat};
use crate::docker_args::DockerCommand;

/// 監査イベント (JSONL 出力用)
#[derive(Debug, Serialize)]
pub struct AuditEvent {
    pub timestamp_unix_nano: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub command: String,
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docker_subcommand: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docker_image: Option<String>,
    pub bind_mounts: Vec<String>,
    pub dangerous_flags: Vec<String>,
    pub cwd: String,
    pub pid: u32,
    pub host_name: String,
    pub environment: String,
    /// 実行モード ("hook" or "wrapper")
    pub mode: String,
}

/// DockerCommand からメタデータを蓄積するコレクター
#[derive(Debug, Default)]
pub struct AuditCollector {
    pub docker_subcommands: Vec<String>,
    pub images: Vec<String>,
    pub bind_mounts: Vec<String>,
    pub dangerous_flags: Vec<String>,
}

impl AuditCollector {
    pub fn new() -> Self {
        Self::default()
    }

    /// DockerCommand のメタデータを収集する
    pub fn record_docker_command(&mut self, cmd: &DockerCommand) {
        self.docker_subcommands.push(cmd.subcommand.to_string());

        if let Some(image) = &cmd.image {
            self.images.push(image.clone());
        }

        for mount in &cmd.bind_mounts {
            self.bind_mounts.push(mount.host_path.clone());
        }

        for flag in &cmd.dangerous_flags {
            self.dangerous_flags.push(flag.to_string());
        }
    }
}

/// 監査ログが有効かどうか判定する
pub fn is_enabled(config: &AuditConfig) -> bool {
    config.enabled || std::env::var("SAFE_DOCKER_AUDIT").is_ok_and(|v| v == "1")
}

/// 監査イベントを構築する
pub fn build_event(
    command: &str,
    decision: &str,
    reason: Option<&str>,
    collector: &AuditCollector,
    session_id: Option<&str>,
    cwd: &str,
    mode: &str,
) -> AuditEvent {
    let timestamp_unix_nano = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;

    let docker_subcommand = collector.docker_subcommands.first().cloned();
    let docker_image = collector.images.first().cloned();

    let host_name = gethostname::gethostname().to_string_lossy().to_string();

    let environment =
        std::env::var("SAFE_DOCKER_ENV").unwrap_or_else(|_| "development".to_string());

    AuditEvent {
        timestamp_unix_nano,
        session_id: session_id.map(String::from),
        command: command.to_string(),
        decision: decision.to_string(),
        reason: reason.map(String::from),
        docker_subcommand,
        docker_image,
        bind_mounts: collector.bind_mounts.clone(),
        dangerous_flags: collector.dangerous_flags.clone(),
        cwd: cwd.to_string(),
        pid: std::process::id(),
        host_name,
        environment,
        mode: mode.to_string(),
    }
}

/// 監査イベントを出力する
pub fn emit(event: &AuditEvent, config: &AuditConfig) {
    match config.format {
        AuditFormat::Jsonl => {
            write_jsonl(event, &config.jsonl_path);
        }
        AuditFormat::Otlp => {
            write_otlp(event, &config.otlp_path);
        }
        AuditFormat::Both => {
            write_jsonl(event, &config.jsonl_path);
            write_otlp(event, &config.otlp_path);
        }
    }
}

/// JSONL 形式でファイルに追記する
fn write_jsonl(event: &AuditEvent, path: &str) {
    let path = expand_tilde(path);
    if let Err(e) = ensure_parent_dir(&path) {
        log::warn!("Failed to create audit log directory for {}: {}", path, e);
        return;
    }

    let line = match serde_json::to_string(event) {
        Ok(json) => json,
        Err(e) => {
            log::warn!("Failed to serialize audit event: {}", e);
            return;
        }
    };

    match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(mut file) => {
            if let Err(e) = writeln!(file, "{}", line) {
                log::warn!("Failed to write audit log to {}: {}", path, e);
            }
        }
        Err(e) => {
            log::warn!("Failed to open audit log file {}: {}", path, e);
        }
    }
}

/// OTLP JSON Lines 形式でファイルに追記する
#[cfg(feature = "otlp")]
fn write_otlp(event: &AuditEvent, path: &str) {
    use opentelemetry_proto::tonic::collector::logs::v1::ExportLogsServiceRequest;
    use opentelemetry_proto::tonic::common::v1::{AnyValue, any_value};
    use opentelemetry_proto::tonic::logs::v1::{LogRecord, ResourceLogs, ScopeLogs};
    use opentelemetry_proto::tonic::resource::v1::Resource;

    let path = expand_tilde(path);
    if let Err(e) = ensure_parent_dir(&path) {
        log::warn!("Failed to create audit log directory for {}: {}", path, e);
        return;
    }

    // Severity マッピング
    let (severity_number, severity_text) = match event.decision.as_str() {
        "allow" => (9, "INFO"),  // SEVERITY_NUMBER_INFO
        "ask" => (13, "WARN"),   // SEVERITY_NUMBER_WARN
        "deny" => (17, "ERROR"), // SEVERITY_NUMBER_ERROR
        _ => (0, "UNSPECIFIED"),
    };

    // LogRecord 属性を構築
    let mut attributes = vec![
        kv_string("decision", &event.decision),
        kv_string("command", &event.command),
        kv_string("cwd", &event.cwd),
    ];

    if let Some(ref session_id) = event.session_id {
        attributes.push(kv_string("session_id", session_id));
    }
    if let Some(ref subcmd) = event.docker_subcommand {
        attributes.push(kv_string("docker.subcommand", subcmd));
    }
    if let Some(ref image) = event.docker_image {
        attributes.push(kv_string("docker.image", image));
    }
    if !event.bind_mounts.is_empty() {
        attributes.push(kv_string_array("docker.bind_mounts", &event.bind_mounts));
    }
    if !event.dangerous_flags.is_empty() {
        attributes.push(kv_string_array(
            "docker.dangerous_flags",
            &event.dangerous_flags,
        ));
    }
    attributes.push(kv_int("process.pid", event.pid as i64));
    attributes.push(kv_string("safe_docker.mode", &event.mode));

    let body = event.reason.as_ref().map(|r| AnyValue {
        value: Some(any_value::Value::StringValue(r.clone())),
    });

    let log_record = LogRecord {
        time_unix_nano: event.timestamp_unix_nano,
        observed_time_unix_nano: event.timestamp_unix_nano,
        severity_number,
        severity_text: severity_text.to_string(),
        body,
        attributes,
        flags: 0,
        ..Default::default()
    };

    // Resource 属性
    let resource_attributes = vec![
        kv_string("service.name", "safe-docker"),
        kv_string("service.version", env!("CARGO_PKG_VERSION")),
        kv_string("deployment.environment.name", &event.environment),
        kv_string("host.name", &event.host_name),
    ];

    let request = ExportLogsServiceRequest {
        resource_logs: vec![ResourceLogs {
            resource: Some(Resource {
                attributes: resource_attributes,
                ..Default::default()
            }),
            scope_logs: vec![ScopeLogs {
                log_records: vec![log_record],
                ..Default::default()
            }],
            ..Default::default()
        }],
    };

    let line = match serde_json::to_string(&request) {
        Ok(json) => json,
        Err(e) => {
            log::warn!("Failed to serialize OTLP audit event: {}", e);
            return;
        }
    };

    match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(mut file) => {
            if let Err(e) = writeln!(file, "{}", line) {
                log::warn!("Failed to write OTLP audit log to {}: {}", path, e);
            }
        }
        Err(e) => {
            log::warn!("Failed to open OTLP audit log file {}: {}", path, e);
        }
    }
}

/// OTLP feature が無効の場合のスタブ
#[cfg(not(feature = "otlp"))]
fn write_otlp(_event: &AuditEvent, path: &str) {
    log::warn!(
        "OTLP audit format requested but 'otlp' feature is not enabled. \
         Skipping write to {}. Build with --features otlp to enable.",
        path
    );
}

/// ~ をホームディレクトリに展開する
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/")
        && let Some(home) = dirs::home_dir()
    {
        return format!("{}/{}", home.display(), rest);
    }
    path.to_string()
}

/// 親ディレクトリが存在しない場合は作成する
fn ensure_parent_dir(path: &str) -> std::io::Result<()> {
    if let Some(parent) = std::path::Path::new(path).parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

// --- OTLP ヘルパー関数 ---

#[cfg(feature = "otlp")]
fn kv_string(key: &str, value: &str) -> opentelemetry_proto::tonic::common::v1::KeyValue {
    use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
    KeyValue {
        key: key.to_string(),
        value: Some(AnyValue {
            value: Some(any_value::Value::StringValue(value.to_string())),
        }),
    }
}

#[cfg(feature = "otlp")]
fn kv_int(key: &str, value: i64) -> opentelemetry_proto::tonic::common::v1::KeyValue {
    use opentelemetry_proto::tonic::common::v1::{AnyValue, KeyValue, any_value};
    KeyValue {
        key: key.to_string(),
        value: Some(AnyValue {
            value: Some(any_value::Value::IntValue(value)),
        }),
    }
}

#[cfg(feature = "otlp")]
fn kv_string_array(
    key: &str,
    values: &[String],
) -> opentelemetry_proto::tonic::common::v1::KeyValue {
    use opentelemetry_proto::tonic::common::v1::{AnyValue, ArrayValue, KeyValue, any_value};
    KeyValue {
        key: key.to_string(),
        value: Some(AnyValue {
            value: Some(any_value::Value::ArrayValue(ArrayValue {
                values: values
                    .iter()
                    .map(|v| AnyValue {
                        value: Some(any_value::Value::StringValue(v.clone())),
                    })
                    .collect(),
            })),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::docker_args::{
        BindMount, DangerousFlag, DockerCommand, DockerSubcommand, MountSource,
    };

    #[test]
    fn test_is_enabled_config() {
        let mut config = AuditConfig::default();
        assert!(!is_enabled(&config));

        config.enabled = true;
        assert!(is_enabled(&config));
    }

    #[test]
    fn test_is_enabled_env_var() {
        let config = AuditConfig::default();
        // 注意: 他のテストとの並行実行で干渉する可能性があるが、
        // 環境変数の検証のために必要
        // SAFETY: テスト実行時のみ使用。並行テストでの競合リスクは許容。
        unsafe { std::env::set_var("SAFE_DOCKER_AUDIT", "1") };
        assert!(is_enabled(&config));
        unsafe { std::env::remove_var("SAFE_DOCKER_AUDIT") };
    }

    #[test]
    fn test_is_enabled_env_var_not_one() {
        let config = AuditConfig::default();
        // SAFETY: テスト実行時のみ使用
        unsafe { std::env::set_var("SAFE_DOCKER_AUDIT", "0") };
        assert!(!is_enabled(&config));
        unsafe { std::env::remove_var("SAFE_DOCKER_AUDIT") };
    }

    #[test]
    fn test_build_event_basic() {
        let collector = AuditCollector::new();
        let event = build_event(
            "docker run ubuntu",
            "allow",
            None,
            &collector,
            Some("session-123"),
            "/home/user/project",
            "hook",
        );

        assert_eq!(event.command, "docker run ubuntu");
        assert_eq!(event.decision, "allow");
        assert!(event.reason.is_none());
        assert_eq!(event.session_id.as_deref(), Some("session-123"));
        assert_eq!(event.cwd, "/home/user/project");
        assert_eq!(event.mode, "hook");
        assert!(event.timestamp_unix_nano > 0);
        assert!(event.pid > 0);
        assert!(!event.host_name.is_empty());
    }

    #[test]
    fn test_build_event_wrapper_mode() {
        let collector = AuditCollector::new();
        let event = build_event(
            "docker run ubuntu",
            "allow",
            None,
            &collector,
            None,
            "/home/user/project",
            "wrapper",
        );

        assert_eq!(event.mode, "wrapper");
    }

    #[test]
    fn test_event_mode_in_jsonl_output() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mode-test.jsonl");
        let path_str = path.to_str().unwrap();

        let collector = AuditCollector::new();
        let event = build_event("docker ps", "allow", None, &collector, None, "/tmp", "wrapper");

        write_jsonl(&event, path_str);

        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(parsed["mode"], "wrapper");
    }

    #[test]
    fn test_build_event_with_reason() {
        let collector = AuditCollector::new();
        let event = build_event(
            "docker run --privileged ubuntu",
            "deny",
            Some("--privileged is not allowed"),
            &collector,
            None,
            "/tmp",
            "hook",
        );

        assert_eq!(event.decision, "deny");
        assert_eq!(event.reason.as_deref(), Some("--privileged is not allowed"));
        assert!(event.session_id.is_none());
    }

    #[test]
    fn test_collector_record_docker_command() {
        let mut collector = AuditCollector::new();
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

        collector.record_docker_command(&cmd);

        assert_eq!(collector.docker_subcommands, vec!["run"]);
        assert_eq!(collector.images, vec!["ubuntu"]);
        assert_eq!(collector.bind_mounts, vec!["/etc"]);
        assert_eq!(collector.dangerous_flags, vec!["--privileged"]);
    }

    #[test]
    fn test_collector_multiple_commands() {
        let mut collector = AuditCollector::new();
        let cmd1 = DockerCommand {
            subcommand: DockerSubcommand::Run,
            bind_mounts: vec![],
            dangerous_flags: vec![],
            compose_file: None,
            image: Some("ubuntu".to_string()),
            host_paths: vec![],
        };
        let cmd2 = DockerCommand {
            subcommand: DockerSubcommand::Build,
            bind_mounts: vec![],
            dangerous_flags: vec![],
            compose_file: None,
            image: None,
            host_paths: vec![],
        };

        collector.record_docker_command(&cmd1);
        collector.record_docker_command(&cmd2);

        assert_eq!(collector.docker_subcommands, vec!["run", "build"]);
        assert_eq!(collector.images, vec!["ubuntu"]);
    }

    #[test]
    fn test_build_event_with_collector_data() {
        let mut collector = AuditCollector::new();
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
                    host_path: "/var/log".to_string(),
                    container_path: "/logs".to_string(),
                    source: MountSource::MountFlag,
                    read_only: true,
                },
            ],
            dangerous_flags: vec![
                DangerousFlag::Privileged,
                DangerousFlag::CapAdd("SYS_ADMIN".to_string()),
            ],
            compose_file: None,
            image: Some("nginx:latest".to_string()),
            host_paths: vec![],
        };
        collector.record_docker_command(&cmd);

        let event = build_event(
            "docker run --privileged --cap-add SYS_ADMIN -v /etc:/data nginx:latest",
            "deny",
            Some("multiple issues"),
            &collector,
            Some("sess-456"),
            "/home/user",
            "hook",
        );

        assert_eq!(event.docker_subcommand.as_deref(), Some("run"));
        assert_eq!(event.docker_image.as_deref(), Some("nginx:latest"));
        assert_eq!(event.bind_mounts, vec!["/etc", "/var/log"]);
        assert_eq!(
            event.dangerous_flags,
            vec!["--privileged", "--cap-add=SYS_ADMIN"]
        );
    }

    #[test]
    fn test_write_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test-audit.jsonl");
        let path_str = path.to_str().unwrap();

        let collector = AuditCollector::new();
        let event = build_event("docker run ubuntu", "allow", None, &collector, None, "/tmp", "hook");

        write_jsonl(&event, path_str);

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.trim().lines().collect();
        assert_eq!(lines.len(), 1);

        // パースできることを確認
        let parsed: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(parsed["decision"], "allow");
        assert_eq!(parsed["command"], "docker run ubuntu");
    }

    #[test]
    fn test_write_jsonl_append() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test-audit.jsonl");
        let path_str = path.to_str().unwrap();

        let collector = AuditCollector::new();
        let event1 = build_event("docker run ubuntu", "allow", None, &collector, None, "/tmp", "hook");
        let event2 = build_event(
            "docker run --privileged ubuntu",
            "deny",
            Some("not allowed"),
            &collector,
            None,
            "/tmp",
            "hook",
        );

        write_jsonl(&event1, path_str);
        write_jsonl(&event2, path_str);

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.trim().lines().collect();
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn test_write_jsonl_creates_parent_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subdir").join("deep").join("audit.jsonl");
        let path_str = path.to_str().unwrap();

        let collector = AuditCollector::new();
        let event = build_event("docker ps", "allow", None, &collector, None, "/tmp", "hook");

        write_jsonl(&event, path_str);

        assert!(path.exists());
    }

    #[test]
    fn test_emit_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let jsonl_path = dir.path().join("audit.jsonl");

        let config = AuditConfig {
            enabled: true,
            format: AuditFormat::Jsonl,
            jsonl_path: jsonl_path.to_str().unwrap().to_string(),
            otlp_path: dir.path().join("otlp.jsonl").to_str().unwrap().to_string(),
        };

        let collector = AuditCollector::new();
        let event = build_event("docker run alpine", "allow", None, &collector, None, "/tmp", "hook");

        emit(&event, &config);

        assert!(jsonl_path.exists());
        let content = std::fs::read_to_string(&jsonl_path).unwrap();
        assert!(content.contains("docker run alpine"));
    }

    #[test]
    fn test_expand_tilde() {
        let expanded = expand_tilde("~/test/path");
        assert!(!expanded.starts_with('~'));
        assert!(expanded.ends_with("test/path"));

        // チルダなしはそのまま
        let no_tilde = expand_tilde("/absolute/path");
        assert_eq!(no_tilde, "/absolute/path");
    }

    #[test]
    fn test_event_serialization() {
        let collector = AuditCollector::new();
        let event = build_event("docker ps", "allow", None, &collector, None, "/tmp", "hook");

        let json = serde_json::to_string(&event).unwrap();
        // None フィールドはスキップされること
        assert!(!json.contains("\"reason\""));
        assert!(!json.contains("\"session_id\""));
        assert!(!json.contains("\"docker_subcommand\""));
        assert!(!json.contains("\"docker_image\""));
        // 必須フィールドは存在すること
        assert!(json.contains("\"command\""));
        assert!(json.contains("\"decision\""));
        assert!(json.contains("\"cwd\""));
        assert!(json.contains("\"pid\""));
        assert!(json.contains("\"host_name\""));
        assert!(json.contains("\"environment\""));
    }

    #[cfg(feature = "otlp")]
    mod otlp_tests {
        use super::*;

        #[test]
        fn test_write_otlp() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("test-otlp.jsonl");
            let path_str = path.to_str().unwrap();

            let mut collector = AuditCollector::new();
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
            collector.record_docker_command(&cmd);

            let event = build_event(
                "docker run --privileged -v /etc:/data ubuntu",
                "deny",
                Some("--privileged is not allowed"),
                &collector,
                Some("session-otlp"),
                "/home/user",
                "hook",
            );

            write_otlp(&event, path_str);

            let content = std::fs::read_to_string(&path).unwrap();
            let lines: Vec<&str> = content.trim().lines().collect();
            assert_eq!(lines.len(), 1);

            // パースできることを確認
            let parsed: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
            // resource_logs が存在する
            assert!(parsed["resourceLogs"].is_array());
            let resource_logs = &parsed["resourceLogs"][0];
            // resource 属性に service.name がある
            let resource_attrs = &resource_logs["resource"]["attributes"];
            let service_name = resource_attrs
                .as_array()
                .unwrap()
                .iter()
                .find(|kv| kv["key"] == "service.name")
                .unwrap();
            assert_eq!(service_name["value"]["stringValue"], "safe-docker");
        }

        #[test]
        fn test_emit_otlp() {
            let dir = tempfile::tempdir().unwrap();
            let otlp_path = dir.path().join("otlp.jsonl");

            let config = AuditConfig {
                enabled: true,
                format: AuditFormat::Otlp,
                jsonl_path: dir.path().join("audit.jsonl").to_str().unwrap().to_string(),
                otlp_path: otlp_path.to_str().unwrap().to_string(),
            };

            let collector = AuditCollector::new();
            let event = build_event("docker run alpine", "allow", None, &collector, None, "/tmp", "hook");

            emit(&event, &config);

            assert!(otlp_path.exists());
        }

        #[test]
        fn test_emit_both() {
            let dir = tempfile::tempdir().unwrap();
            let jsonl_path = dir.path().join("audit.jsonl");
            let otlp_path = dir.path().join("otlp.jsonl");

            let config = AuditConfig {
                enabled: true,
                format: AuditFormat::Both,
                jsonl_path: jsonl_path.to_str().unwrap().to_string(),
                otlp_path: otlp_path.to_str().unwrap().to_string(),
            };

            let collector = AuditCollector::new();
            let event = build_event("docker ps", "allow", None, &collector, None, "/tmp", "hook");

            emit(&event, &config);

            assert!(jsonl_path.exists());
            assert!(otlp_path.exists());
        }
    }
}
