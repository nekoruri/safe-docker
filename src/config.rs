use serde::Deserialize;
use std::path::PathBuf;

use crate::error::{Result, SafeDockerError};

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
        self.blocked_flags.iter().any(|blocked| {
            flag == blocked.as_str() || flag.starts_with(&format!("{}=", blocked))
        })
    }

    /// capability がブロック対象か判定
    pub fn is_capability_blocked(&self, cap: &str) -> bool {
        let cap_upper = cap.to_uppercase();
        self.blocked_capabilities
            .iter()
            .any(|blocked| cap_upper == blocked.to_uppercase())
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
}
