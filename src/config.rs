use serde::Deserialize;
use std::collections::HashSet;
use std::path::PathBuf;

use crate::error::{Result, SafeDockerError};

/// バリデーション結果の問題点
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigIssue {
    /// 設定が無効（修正必須）
    Error(String),
    /// 意図しない可能性がある設定（修正推奨）
    Warning(String),
}

/// 監査ログの出力形式
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuditFormat {
    #[default]
    Jsonl,
    Otlp,
    Both,
}

/// 非対話環境での ask の扱い
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NonInteractiveAsk {
    #[default]
    Deny,
    Allow,
}

/// ラッパーモード設定
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct WrapperConfig {
    /// 本物の docker バイナリパス（空=自動検出）
    pub docker_path: String,
    /// 非対話環境での ask の扱い ("deny" / "allow")
    pub non_interactive_ask: NonInteractiveAsk,
}

impl Default for WrapperConfig {
    fn default() -> Self {
        Self {
            docker_path: String::new(),
            non_interactive_ask: NonInteractiveAsk::Deny,
        }
    }
}

/// 監査ログ設定
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AuditConfig {
    /// 監査ログの有効/無効 (環境変数 SAFE_DOCKER_AUDIT=1 でも有効化可能)
    pub enabled: bool,
    /// 出力形式
    pub format: AuditFormat,
    /// JSONL ファイルのパス
    pub jsonl_path: String,
    /// OTLP JSON Lines ファイルのパス (feature gate しない: TOML パース互換性のため)
    pub otlp_path: String,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            format: AuditFormat::Jsonl,
            jsonl_path: "~/.local/share/safe-docker/audit.jsonl".to_string(),
            otlp_path: "~/.local/share/safe-docker/audit-otlp.jsonl".to_string(),
        }
    }
}

/// 設定ファイルのデフォルトパス
fn default_config_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("safe-docker")
        .join("config.toml")
}

/// $HOME 配下で ask にするデフォルトの機密パス (相対)
fn default_sensitive_paths() -> Vec<String> {
    vec![
        ".ssh".to_string(),
        ".aws".to_string(),
        ".gnupg".to_string(),
        ".docker".to_string(),
        ".kube".to_string(),
        ".config/gcloud".to_string(),
        ".claude".to_string(),
    ]
}

/// デフォルトでブロックする危険フラグ
fn default_blocked_flags() -> Vec<String> {
    vec![
        "--privileged".to_string(),
        "--pid=host".to_string(),
        "--network=host".to_string(),
    ]
}

/// デフォルトでブロックする危険 capability
fn default_blocked_capabilities() -> Vec<String> {
    vec![
        "SYS_ADMIN".to_string(),
        "SYS_PTRACE".to_string(),
        "SYS_MODULE".to_string(),
        "SYS_RAWIO".to_string(),
        "ALL".to_string(),
    ]
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct Config {
    /// $HOME 外で追加許可するパス
    pub allowed_paths: Vec<String>,

    /// $HOME 配下で ask にする機密パス (ホームからの相対)
    pub sensitive_paths: Vec<String>,

    /// 追加ブロックフラグ
    pub blocked_flags: Vec<String>,

    /// ブロックする capability
    pub blocked_capabilities: Vec<String>,

    /// イメージホワイトリスト (空=制限なし)
    pub allowed_images: Vec<String>,

    /// Docker ソケットマウントの禁止
    pub block_docker_socket: bool,

    /// 監査ログ設定
    #[serde(default)]
    pub audit: AuditConfig,

    /// ラッパーモード設定
    #[serde(default)]
    pub wrapper: WrapperConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            allowed_paths: Vec::new(),
            sensitive_paths: default_sensitive_paths(),
            blocked_flags: default_blocked_flags(),
            blocked_capabilities: default_blocked_capabilities(),
            allowed_images: Vec::new(),
            block_docker_socket: true,
            audit: AuditConfig::default(),
            wrapper: WrapperConfig::default(),
        }
    }
}

impl Config {
    /// 設定ファイルを読み込む。ファイルが存在しない場合はデフォルト値を返す。
    pub fn load() -> Result<Self> {
        let path = default_config_path();
        Self::load_from(&path)
    }

    /// 指定パスから設定を読み込む
    pub fn load_from(path: &std::path::Path) -> Result<Self> {
        if !path.exists() {
            log::debug!("Config file not found at {:?}, using defaults", path);
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(path).map_err(SafeDockerError::Io)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    /// パスが allowed_paths に含まれるか判定
    pub fn is_path_allowed(&self, canonical_path: &str) -> bool {
        self.allowed_paths.iter().any(|allowed| {
            let allowed_canonical = std::fs::canonicalize(allowed)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|_| allowed.clone());
            canonical_path.starts_with(&allowed_canonical)
        })
    }

    /// パスが sensitive_paths に含まれるか判定
    pub fn is_path_sensitive(&self, path_relative_to_home: &str) -> bool {
        self.sensitive_paths
            .iter()
            .any(|sensitive| path_relative_to_home.starts_with(sensitive))
    }

    /// フラグがブロック対象か判定
    pub fn is_flag_blocked(&self, flag: &str) -> bool {
        self.blocked_flags
            .iter()
            .any(|blocked| flag == blocked.as_str() || flag.starts_with(&format!("{}=", blocked)))
    }

    /// capability がブロック対象か判定
    pub fn is_capability_blocked(&self, cap: &str) -> bool {
        let cap_upper = cap.to_uppercase();
        self.blocked_capabilities
            .iter()
            .any(|blocked| cap_upper == blocked.to_uppercase())
    }

    /// 設定のバリデーションを行い、問題点のリストを返す
    pub fn validate(&self) -> Vec<ConfigIssue> {
        let mut issues = Vec::new();

        // allowed_paths: 絶対パスであること
        for (i, path) in self.allowed_paths.iter().enumerate() {
            if path.is_empty() {
                issues.push(ConfigIssue::Error(format!(
                    "allowed_paths[{}]: empty string",
                    i
                )));
            } else if !path.starts_with('/') && !path.starts_with('~') {
                issues.push(ConfigIssue::Error(format!(
                    "allowed_paths[{}]: '{}' is not an absolute path (must start with '/' or '~')",
                    i, path
                )));
            }
        }

        // allowed_paths: 存在しないパスの警告
        for path in &self.allowed_paths {
            if !path.is_empty() && path.starts_with('/') && !PathBuf::from(path).exists() {
                issues.push(ConfigIssue::Warning(format!(
                    "allowed_paths: '{}' does not exist",
                    path
                )));
            }
        }

        // allowed_paths: 重複チェック
        check_duplicates(&self.allowed_paths, "allowed_paths", &mut issues);

        // sensitive_paths: 相対パスであること
        for (i, path) in self.sensitive_paths.iter().enumerate() {
            if path.is_empty() {
                issues.push(ConfigIssue::Error(format!(
                    "sensitive_paths[{}]: empty string",
                    i
                )));
            } else if path.starts_with('/') {
                issues.push(ConfigIssue::Error(format!(
                    "sensitive_paths[{}]: '{}' must be a relative path (relative to $HOME)",
                    i, path
                )));
            }
        }

        // sensitive_paths: 重複チェック
        check_duplicates(&self.sensitive_paths, "sensitive_paths", &mut issues);

        // blocked_flags: -- で始まること
        for (i, flag) in self.blocked_flags.iter().enumerate() {
            if flag.is_empty() {
                issues.push(ConfigIssue::Error(format!(
                    "blocked_flags[{}]: empty string",
                    i
                )));
            } else if !flag.starts_with("--") {
                issues.push(ConfigIssue::Error(format!(
                    "blocked_flags[{}]: '{}' must start with '--'",
                    i, flag
                )));
            }
        }

        // blocked_flags: 重複チェック
        check_duplicates(&self.blocked_flags, "blocked_flags", &mut issues);

        // blocked_capabilities: 有効な capability 名の形式
        for (i, cap) in self.blocked_capabilities.iter().enumerate() {
            if cap.is_empty() {
                issues.push(ConfigIssue::Error(format!(
                    "blocked_capabilities[{}]: empty string",
                    i
                )));
            } else if !is_valid_capability_name(cap) {
                issues.push(ConfigIssue::Error(format!(
                    "blocked_capabilities[{}]: '{}' is not a valid Linux capability name (expected uppercase like SYS_ADMIN, NET_RAW, ALL)",
                    i, cap
                )));
            }
        }

        // blocked_capabilities: 重複チェック (大文字小文字無視)
        {
            let mut seen = HashSet::new();
            for cap in &self.blocked_capabilities {
                let upper = cap.to_uppercase();
                if !seen.insert(upper) {
                    issues.push(ConfigIssue::Warning(format!(
                        "blocked_capabilities: '{}' is duplicated",
                        cap
                    )));
                }
            }
        }

        // allowed_images: 空文字列でないこと
        for (i, image) in self.allowed_images.iter().enumerate() {
            if image.is_empty() {
                issues.push(ConfigIssue::Error(format!(
                    "allowed_images[{}]: empty string",
                    i
                )));
            }
        }

        // allowed_images: 重複チェック
        check_duplicates(&self.allowed_images, "allowed_images", &mut issues);

        // audit パスの検証
        if self.audit.enabled {
            if self.audit.jsonl_path.is_empty()
                && matches!(self.audit.format, AuditFormat::Jsonl | AuditFormat::Both)
            {
                issues.push(ConfigIssue::Error(
                    "audit.jsonl_path: empty string (required when format is 'jsonl' or 'both')"
                        .to_string(),
                ));
            }
            if self.audit.otlp_path.is_empty()
                && matches!(self.audit.format, AuditFormat::Otlp | AuditFormat::Both)
            {
                issues.push(ConfigIssue::Error(
                    "audit.otlp_path: empty string (required when format is 'otlp' or 'both')"
                        .to_string(),
                ));
            }
        }

        issues
    }
}

/// 有効な Linux capability 名か判定
/// ALL, または大文字英字とアンダースコアで構成される名前
fn is_valid_capability_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let upper = name.to_uppercase();
    upper.chars().all(|c| c.is_ascii_uppercase() || c == '_')
        && upper.starts_with(|c: char| c.is_ascii_uppercase())
}

/// 重複チェック
fn check_duplicates(items: &[String], field_name: &str, issues: &mut Vec<ConfigIssue>) {
    let mut seen = HashSet::new();
    for item in items {
        if !item.is_empty() && !seen.insert(item) {
            issues.push(ConfigIssue::Warning(format!(
                "{}: '{}' is duplicated",
                field_name, item
            )));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert!(config.sensitive_paths.contains(&".ssh".to_string()));
        assert!(config.blocked_flags.contains(&"--privileged".to_string()));
        assert!(config.allowed_paths.is_empty());
        assert!(config.block_docker_socket);
    }

    #[test]
    fn test_is_capability_blocked() {
        let config = Config::default();
        assert!(config.is_capability_blocked("SYS_ADMIN"));
        assert!(config.is_capability_blocked("sys_admin"));
        assert!(config.is_capability_blocked("ALL"));
        assert!(!config.is_capability_blocked("NET_ADMIN"));
    }

    #[test]
    fn test_is_flag_blocked() {
        let config = Config::default();
        assert!(config.is_flag_blocked("--privileged"));
        assert!(config.is_flag_blocked("--pid=host"));
        assert!(!config.is_flag_blocked("--rm"));
    }

    #[test]
    fn test_is_path_sensitive() {
        let config = Config::default();
        assert!(config.is_path_sensitive(".ssh"));
        assert!(config.is_path_sensitive(".ssh/id_rsa"));
        assert!(config.is_path_sensitive(".aws/credentials"));
        assert!(!config.is_path_sensitive("projects/myapp"));
    }

    #[test]
    fn test_load_nonexistent_file() {
        let config = Config::load_from(std::path::Path::new("/nonexistent/config.toml")).unwrap();
        assert_eq!(config.sensitive_paths, default_sensitive_paths());
    }

    #[test]
    fn test_parse_toml() {
        let toml_str = r#"
            allowed_paths = ["/tmp/docker-data"]
            sensitive_paths = [".ssh", ".aws"]
            blocked_flags = ["--privileged"]
            blocked_capabilities = ["SYS_ADMIN"]
            allowed_images = ["ubuntu", "alpine"]
            block_docker_socket = true
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.allowed_paths, vec!["/tmp/docker-data"]);
        assert_eq!(config.allowed_images, vec!["ubuntu", "alpine"]);
    }

    // --- 設定ファイルテスト ---

    #[test]
    fn test_parse_invalid_toml() {
        let result: std::result::Result<Config, _> = toml::from_str("{{invalid toml");
        assert!(result.is_err(), "Invalid TOML should produce an error");
    }

    #[test]
    fn test_parse_partial_config() {
        // 一部のキーのみ指定 → 未指定分はデフォルト
        let toml_str = r#"
            allowed_paths = ["/opt/data"]
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.allowed_paths, vec!["/opt/data"]);
        // 未指定キーはデフォルト
        assert_eq!(config.sensitive_paths, default_sensitive_paths());
        assert_eq!(config.blocked_flags, default_blocked_flags());
        assert!(config.block_docker_socket);
    }

    #[test]
    fn test_parse_empty_toml() {
        let config: Config = toml::from_str("").unwrap();
        assert_eq!(config.sensitive_paths, default_sensitive_paths());
        assert_eq!(config.blocked_flags, default_blocked_flags());
        assert_eq!(config.blocked_capabilities, default_blocked_capabilities());
        assert!(config.allowed_paths.is_empty());
        assert!(config.allowed_images.is_empty());
        assert!(config.block_docker_socket);
    }

    #[test]
    fn test_is_path_allowed_canonicalize() {
        // allowed_paths に /tmp を追加
        let mut config = Config::default();
        config.allowed_paths = vec!["/tmp".to_string()];
        // /tmp 配下のパスは許可される
        assert!(config.is_path_allowed("/tmp/docker-data"));
        assert!(config.is_path_allowed("/tmp"));
        // /tmp 外は不許可
        assert!(!config.is_path_allowed("/etc/passwd"));
    }

    #[test]
    fn test_is_path_allowed_nonexistent() {
        // 存在しないパスの場合は文字列比較
        let mut config = Config::default();
        config.allowed_paths = vec!["/nonexistent/path".to_string()];
        assert!(config.is_path_allowed("/nonexistent/path/subdir"));
    }

    #[test]
    fn test_load_from_tempfile() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.toml");
        std::fs::write(
            &config_path,
            r#"
                allowed_images = ["myimage"]
                block_docker_socket = false
            "#,
        )
        .unwrap();

        let config = Config::load_from(&config_path).unwrap();
        assert_eq!(config.allowed_images, vec!["myimage"]);
        assert!(!config.block_docker_socket);
    }

    #[test]
    fn test_is_flag_blocked_equals_prefix() {
        let config = Config::default();
        // --network=host → blocked_flags に "--network=host" がある
        assert!(config.is_flag_blocked("--network=host"));
        // --privileged → 完全一致
        assert!(config.is_flag_blocked("--privileged"));
        // 存在しないフラグ
        assert!(!config.is_flag_blocked("--rm"));
    }

    #[test]
    fn test_block_docker_socket_false() {
        let mut config = Config::default();
        config.block_docker_socket = false;
        // block_docker_socket が false の場合、設定レベルではチェックしない
        // (path_validator で使われるが、config 自体のテスト)
        assert!(!config.block_docker_socket);
    }

    // --- AuditConfig テスト ---

    #[test]
    fn test_audit_config_default() {
        let config = AuditConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.format, AuditFormat::Jsonl);
        assert_eq!(config.jsonl_path, "~/.local/share/safe-docker/audit.jsonl");
        assert_eq!(
            config.otlp_path,
            "~/.local/share/safe-docker/audit-otlp.jsonl"
        );
    }

    #[test]
    fn test_audit_config_in_default_config() {
        let config = Config::default();
        assert!(!config.audit.enabled);
        assert_eq!(config.audit.format, AuditFormat::Jsonl);
    }

    #[test]
    fn test_parse_audit_config() {
        let toml_str = r#"
            [audit]
            enabled = true
            format = "both"
            jsonl_path = "/tmp/audit.jsonl"
            otlp_path = "/tmp/audit-otlp.jsonl"
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.audit.enabled);
        assert_eq!(config.audit.format, AuditFormat::Both);
        assert_eq!(config.audit.jsonl_path, "/tmp/audit.jsonl");
        assert_eq!(config.audit.otlp_path, "/tmp/audit-otlp.jsonl");
    }

    #[test]
    fn test_parse_audit_config_otlp_format() {
        let toml_str = r#"
            [audit]
            enabled = true
            format = "otlp"
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.audit.enabled);
        assert_eq!(config.audit.format, AuditFormat::Otlp);
    }

    #[test]
    fn test_parse_config_without_audit_section() {
        let toml_str = r#"
            allowed_paths = ["/tmp"]
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        // audit セクションが省略された場合はデフォルト
        assert!(!config.audit.enabled);
        assert_eq!(config.audit.format, AuditFormat::Jsonl);
    }

    // --- validate() テスト ---

    #[test]
    fn test_validate_default_config() {
        let config = Config::default();
        let issues = config.validate();
        assert!(
            issues.is_empty(),
            "Default config should have no issues: {:?}",
            issues
        );
    }

    #[test]
    fn test_validate_allowed_paths_relative() {
        let mut config = Config::default();
        config.allowed_paths = vec!["relative/path".to_string()];
        let issues = config.validate();
        assert!(
            issues.iter().any(
                |i| matches!(i, ConfigIssue::Error(msg) if msg.contains("not an absolute path"))
            )
        );
    }

    #[test]
    fn test_validate_allowed_paths_tilde() {
        let mut config = Config::default();
        config.allowed_paths = vec!["~/projects".to_string()];
        let issues = config.validate();
        // ~ で始まるパスはエラーにならない
        assert!(
            !issues
                .iter()
                .any(|i| matches!(i, ConfigIssue::Error(msg) if msg.contains("allowed_paths"))),
            "~/... should be accepted: {:?}",
            issues
        );
    }

    #[test]
    fn test_validate_allowed_paths_empty_string() {
        let mut config = Config::default();
        config.allowed_paths = vec!["".to_string()];
        let issues = config.validate();
        assert!(
            issues
                .iter()
                .any(|i| matches!(i, ConfigIssue::Error(msg) if msg.contains("empty string")))
        );
    }

    #[test]
    fn test_validate_allowed_paths_nonexistent_warning() {
        let mut config = Config::default();
        config.allowed_paths = vec!["/nonexistent/path/12345".to_string()];
        let issues = config.validate();
        assert!(
            issues
                .iter()
                .any(|i| matches!(i, ConfigIssue::Warning(msg) if msg.contains("does not exist")))
        );
    }

    #[test]
    fn test_validate_sensitive_paths_absolute() {
        let mut config = Config::default();
        config.sensitive_paths = vec!["/absolute/path".to_string()];
        let issues = config.validate();
        assert!(
            issues
                .iter()
                .any(|i| matches!(i, ConfigIssue::Error(msg) if msg.contains("relative path")))
        );
    }

    #[test]
    fn test_validate_blocked_flags_no_prefix() {
        let mut config = Config::default();
        config.blocked_flags = vec!["privileged".to_string()];
        let issues = config.validate();
        assert!(
            issues.iter().any(
                |i| matches!(i, ConfigIssue::Error(msg) if msg.contains("must start with '--'"))
            )
        );
    }

    #[test]
    fn test_validate_blocked_capabilities_invalid() {
        let mut config = Config::default();
        config.blocked_capabilities = vec!["not-a-capability!".to_string()];
        let issues = config.validate();
        assert!(issues.iter().any(
            |i| matches!(i, ConfigIssue::Error(msg) if msg.contains("not a valid Linux capability"))
        ));
    }

    #[test]
    fn test_validate_blocked_capabilities_valid() {
        let mut config = Config::default();
        config.blocked_capabilities = vec![
            "SYS_ADMIN".to_string(),
            "NET_RAW".to_string(),
            "ALL".to_string(),
        ];
        let issues = config.validate();
        assert!(
            !issues
                .iter()
                .any(|i| matches!(i, ConfigIssue::Error(msg) if msg.contains("capability"))),
            "Valid capabilities should not produce errors: {:?}",
            issues
        );
    }

    #[test]
    fn test_validate_allowed_images_empty_string() {
        let mut config = Config::default();
        config.allowed_images = vec!["".to_string()];
        let issues = config.validate();
        assert!(issues
            .iter()
            .any(|i| matches!(i, ConfigIssue::Error(msg) if msg.contains("allowed_images") && msg.contains("empty string"))));
    }

    #[test]
    fn test_validate_duplicate_allowed_paths() {
        let mut config = Config::default();
        config.allowed_paths = vec!["/tmp".to_string(), "/tmp".to_string()];
        let issues = config.validate();
        assert!(
            issues
                .iter()
                .any(|i| matches!(i, ConfigIssue::Warning(msg) if msg.contains("duplicated")))
        );
    }

    #[test]
    fn test_validate_audit_empty_jsonl_path() {
        let mut config = Config::default();
        config.audit.enabled = true;
        config.audit.format = AuditFormat::Jsonl;
        config.audit.jsonl_path = "".to_string();
        let issues = config.validate();
        assert!(
            issues
                .iter()
                .any(|i| matches!(i, ConfigIssue::Error(msg) if msg.contains("audit.jsonl_path")))
        );
    }

    #[test]
    fn test_validate_audit_empty_otlp_path() {
        let mut config = Config::default();
        config.audit.enabled = true;
        config.audit.format = AuditFormat::Otlp;
        config.audit.otlp_path = "".to_string();
        let issues = config.validate();
        assert!(
            issues
                .iter()
                .any(|i| matches!(i, ConfigIssue::Error(msg) if msg.contains("audit.otlp_path")))
        );
    }

    #[test]
    fn test_validate_audit_disabled_ignores_paths() {
        let mut config = Config::default();
        config.audit.enabled = false;
        config.audit.jsonl_path = "".to_string();
        config.audit.otlp_path = "".to_string();
        let issues = config.validate();
        // audit が無効なら空パスはエラーにならない
        assert!(
            !issues
                .iter()
                .any(|i| matches!(i, ConfigIssue::Error(msg) if msg.contains("audit"))),
            "Disabled audit should not check paths: {:?}",
            issues
        );
    }

    #[test]
    fn test_validate_multiple_errors() {
        let mut config = Config::default();
        config.allowed_paths = vec!["relative".to_string()];
        config.sensitive_paths = vec!["/absolute".to_string()];
        config.blocked_flags = vec!["noprefixed".to_string()];
        let issues = config.validate();
        let error_count = issues
            .iter()
            .filter(|i| matches!(i, ConfigIssue::Error(_)))
            .count();
        assert!(
            error_count >= 3,
            "Should have at least 3 errors: {:?}",
            issues
        );
    }

    #[test]
    fn test_is_valid_capability_name() {
        assert!(is_valid_capability_name("SYS_ADMIN"));
        assert!(is_valid_capability_name("NET_RAW"));
        assert!(is_valid_capability_name("ALL"));
        assert!(is_valid_capability_name("sys_admin")); // lowercase accepted
        assert!(!is_valid_capability_name(""));
        assert!(!is_valid_capability_name("not-valid"));
        assert!(!is_valid_capability_name("123"));
        assert!(!is_valid_capability_name("SYS ADMIN"));
    }
}
