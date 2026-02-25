use std::path::{Path, PathBuf};

use crate::config::Config;

/// パス判定結果
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathVerdict {
    /// $HOME 配下 or allowed_paths — 許可
    Allowed,
    /// $HOME 配下だが .ssh 等の機密パス — ユーザー確認
    Sensitive(String),
    /// $HOME 外 — 拒否
    Denied(String),
    /// パスを解決できない（環境変数未展開等） — ユーザー確認
    Unresolvable(String),
}

/// $HOME ディレクトリを取得
pub fn home_dir() -> Option<PathBuf> {
    dirs::home_dir()
}

/// 環境変数を簡易展開する ($HOME, ~, ${HOME})
pub fn expand_env(path: &str) -> String {
    let home = home_dir()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    let mut result = path.to_string();

    // ~ で始まるパスを展開 (~/... のみ、~user は展開しない)
    if result == "~" {
        return home;
    }
    if let Some(rest) = result.strip_prefix("~/") {
        return format!("{}/{}", home, rest);
    }

    // $HOME, ${HOME} を展開
    result = result.replace("${HOME}", &home);
    result = result.replace("$HOME", &home);

    // $PWD, ${PWD} を展開
    if let Ok(pwd) = std::env::var("PWD") {
        result = result.replace("${PWD}", &pwd);
        result = result.replace("$PWD", &pwd);
    }

    result
}

/// 未展開の環境変数が残っているかチェック
fn has_unresolved_vars(path: &str) -> bool {
    // $文字の後に英字またはアンダースコアが続くパターン
    let bytes = path.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b'$'
            && i + 1 < bytes.len()
            && (bytes[i + 1].is_ascii_alphabetic() || bytes[i + 1] == b'_' || bytes[i + 1] == b'{')
        {
            return true;
        }
    }
    false
}

/// ファイルが存在しなくても動作する論理的なパス正規化。
/// `..` と `.` を解決し、二重スラッシュを正規化する。
fn logical_normalize(path: &Path) -> PathBuf {
    use std::path::Component;
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                // ルートを超えて .. は適用しない
                if !components.is_empty() && !matches!(components.last(), Some(&Component::RootDir))
                {
                    components.pop();
                } else if components.is_empty() {
                    components.push(component);
                }
            }
            Component::CurDir => {
                // `.` は無視
            }
            _ => {
                components.push(component);
            }
        }
    }
    if components.is_empty() {
        PathBuf::from(".")
    } else {
        components.iter().collect()
    }
}

/// パスを正規化して判定する
pub fn validate_path(raw_path: &str, config: &Config) -> PathVerdict {
    // 空パスは拒否
    if raw_path.is_empty() {
        return PathVerdict::Denied("Empty path (specify a host path for the mount)".to_string());
    }

    // 環境変数を展開
    let expanded = expand_env(raw_path);

    // 未展開の変数が残っている場合は解決不能
    if has_unresolved_vars(&expanded) {
        return PathVerdict::Unresolvable(format!(
            "Path contains unresolved variables: {} (only $HOME and $PWD are expanded)",
            raw_path
        ));
    }

    // Docker ソケットのチェック
    if config.block_docker_socket {
        let normalized = expanded.trim_end_matches('/');
        if normalized == "/var/run/docker.sock"
            || normalized == "/run/docker.sock"
            || normalized.ends_with("/docker.sock")
        {
            return PathVerdict::Denied(format!(
                "Docker socket mount is blocked: {} (set block_docker_socket = false in config to allow)",
                raw_path
            ));
        }
    }

    // Docker ソケットの追加チェック: /. や /./ 等の正規化回避を防ぐ
    {
        let logical = logical_normalize(Path::new(&expanded));
        let logical_str = logical.to_string_lossy();
        let logical_trimmed = logical_str.trim_end_matches('/');
        if config.block_docker_socket
            && (logical_trimmed == "/var/run/docker.sock"
                || logical_trimmed == "/run/docker.sock"
                || logical_trimmed.ends_with("/docker.sock"))
        {
            return PathVerdict::Denied(format!(
                "Docker socket mount is blocked: {} (set block_docker_socket = false in config to allow)",
                raw_path
            ));
        }
    }

    // パスを正規化 (canonicalize はシンボリックリンクを解決する)
    let canonical = match std::fs::canonicalize(&expanded) {
        Ok(p) => p,
        Err(_) => {
            // ファイルが存在しない場合は論理正規化で .. 等を処理
            let path = Path::new(&expanded);
            let abs_path = if path.is_absolute() {
                path.to_path_buf()
            } else {
                // 相対パスは CWD を基準に解決を試みる
                match std::env::current_dir() {
                    Ok(cwd) => cwd.join(path),
                    Err(_) => {
                        return PathVerdict::Unresolvable(format!(
                            "Cannot resolve relative path: {} (use an absolute path or $HOME-relative path)",
                            raw_path
                        ));
                    }
                }
            };
            logical_normalize(&abs_path)
        }
    };

    let canonical_str = canonical.to_string_lossy().to_string();

    // allowed_paths のチェック (最優先)
    if config.is_path_allowed(&canonical_str) {
        return PathVerdict::Allowed;
    }

    // $HOME 配下かチェック
    let home = match home_dir() {
        Some(h) => h,
        None => {
            return PathVerdict::Unresolvable(
                "Cannot determine home directory (ensure $HOME is set)".to_string(),
            );
        }
    };

    let home_str = home.to_string_lossy().to_string();
    let home_prefix = format!("{}/", home_str);

    if canonical_str == home_str || canonical_str.starts_with(&home_prefix) {
        // $HOME 配下: 機密パスチェック
        let relative = if canonical_str == home_str {
            ""
        } else {
            &canonical_str[home_prefix.len()..]
        };

        if config.is_path_sensitive(relative) {
            return PathVerdict::Sensitive(format!(
                "Mounting sensitive path {} (resolved: {}) which may contain credentials or keys",
                raw_path, canonical_str
            ));
        }

        return PathVerdict::Allowed;
    }

    // $HOME 外
    PathVerdict::Denied(format!(
        "Path is outside $HOME: {} (resolved: {}). Only $HOME paths or allowed_paths are permitted",
        raw_path, canonical_str
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_env_tilde() {
        let home = home_dir().unwrap().to_string_lossy().to_string();
        assert_eq!(expand_env("~/projects"), format!("{}/projects", home));
        assert_eq!(expand_env("~"), home);
    }

    #[test]
    fn test_expand_env_home_var() {
        let home = home_dir().unwrap().to_string_lossy().to_string();
        assert_eq!(expand_env("$HOME/projects"), format!("{}/projects", home));
        assert_eq!(expand_env("${HOME}/projects"), format!("{}/projects", home));
    }

    #[test]
    fn test_has_unresolved_vars() {
        assert!(has_unresolved_vars("$UNKNOWN/path"));
        assert!(has_unresolved_vars("${FOO}/path"));
        assert!(!has_unresolved_vars("/home/user/path"));
        assert!(!has_unresolved_vars("/path/$")); // $ at end, no var name
    }

    #[test]
    fn test_validate_path_home_allowed() {
        let config = Config::default();
        let home = home_dir().unwrap().to_string_lossy().to_string();
        let test_path = format!("{}/projects/myapp", home);
        let result = validate_path(&test_path, &config);
        assert_eq!(result, PathVerdict::Allowed);
    }

    #[test]
    fn test_validate_path_tilde_allowed() {
        let config = Config::default();
        // ~ は $HOME に展開される → Allowed
        let result = validate_path("~/projects", &config);
        assert_eq!(result, PathVerdict::Allowed);
    }

    #[test]
    fn test_validate_path_outside_home_denied() {
        let config = Config::default();
        let result = validate_path("/etc/passwd", &config);
        assert!(matches!(result, PathVerdict::Denied(_)));
    }

    #[test]
    fn test_validate_path_sensitive() {
        let config = Config::default();
        let home = home_dir().unwrap().to_string_lossy().to_string();
        let result = validate_path(&format!("{}/.ssh/id_rsa", home), &config);
        assert!(matches!(result, PathVerdict::Sensitive(_)));
    }

    #[test]
    fn test_validate_path_docker_socket() {
        let config = Config::default();
        let result = validate_path("/var/run/docker.sock", &config);
        assert!(matches!(result, PathVerdict::Denied(_)));
    }

    #[test]
    fn test_validate_path_unresolved_var() {
        let config = Config::default();
        let result = validate_path("$MYVAR/data", &config);
        assert!(matches!(result, PathVerdict::Unresolvable(_)));
    }

    #[test]
    fn test_validate_path_empty() {
        let config = Config::default();
        let result = validate_path("", &config);
        assert!(matches!(result, PathVerdict::Denied(_)));
    }

    // --- パストラバーサルテスト ---

    #[test]
    fn test_validate_path_traversal_home_to_etc() {
        let config = Config::default();
        let home = home_dir().unwrap().to_string_lossy().to_string();
        let result = validate_path(&format!("{}/../../etc", home), &config);
        assert!(
            matches!(result, PathVerdict::Denied(_)),
            "$HOME/../../etc should be denied: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_path_dot_in_home() {
        let config = Config::default();
        let home = home_dir().unwrap().to_string_lossy().to_string();
        let result = validate_path(&format!("{}/./projects", home), &config);
        assert_eq!(
            result,
            PathVerdict::Allowed,
            "$HOME/./projects should be allowed"
        );
    }

    #[test]
    fn test_validate_path_unresolved_user_var() {
        let config = Config::default();
        let home = home_dir().unwrap().to_string_lossy().to_string();
        let result = validate_path(&format!("{}/../$USER/projects", home), &config);
        assert!(
            matches!(result, PathVerdict::Unresolvable(_)),
            "$HOME/../$USER/projects should be unresolvable: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_path_docker_socket_with_dot() {
        let config = Config::default();
        let result = validate_path("/var/run/docker.sock/.", &config);
        assert!(
            matches!(result, PathVerdict::Denied(_)),
            "/var/run/docker.sock/. should be denied: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_path_double_slash() {
        let config = Config::default();
        let result = validate_path("//etc//passwd", &config);
        assert!(
            matches!(result, PathVerdict::Denied(_)),
            "//etc//passwd should be denied: {:?}",
            result
        );
    }

    #[test]
    fn test_validate_path_home_itself() {
        let config = Config::default();
        let home = home_dir().unwrap().to_string_lossy().to_string();
        let result = validate_path(&home, &config);
        assert_eq!(
            result,
            PathVerdict::Allowed,
            "$HOME itself should be allowed"
        );
    }

    #[test]
    fn test_validate_path_pwd_expansion() {
        let config = Config::default();
        // $PWD は環境変数から展開される
        let result = validate_path("$PWD", &config);
        // $PWD の値によって結果が変わるが、パニックしないことを確認
        assert!(
            !matches!(result, PathVerdict::Unresolvable(_)) || {
                // PWD が設定されていない場合は Unresolvable もあり得る
                std::env::var("PWD").is_err()
            }
        );
    }

    #[test]
    fn test_validate_path_allowed_paths_outside_home() {
        let mut config = Config::default();
        config.allowed_paths = vec!["/tmp".to_string()];
        let result = validate_path("/tmp/docker-data", &config);
        assert_eq!(
            result,
            PathVerdict::Allowed,
            "/tmp should be allowed when in allowed_paths"
        );
    }

    #[test]
    fn test_validate_path_symlink_resolution() {
        use std::os::unix::fs;
        let dir = tempfile::tempdir().unwrap();
        let home = home_dir().unwrap();

        // HOME配下にシンボリックリンクを作成（テスト可能な場合のみ）
        let link_path = home.join(".safe-docker-test-link");
        let target = dir.path();

        // クリーンアップ用
        let _ = std::fs::remove_file(&link_path);

        if fs::symlink(target, &link_path).is_ok() {
            let config = Config::default();
            let result = validate_path(link_path.to_str().unwrap(), &config);

            // シンボリックリンクは解決後のパスで判定される
            // target が $HOME 外なら Denied
            assert!(
                matches!(result, PathVerdict::Denied(_)),
                "Symlink to outside $HOME should be denied: {:?}",
                result
            );

            // クリーンアップ
            let _ = std::fs::remove_file(&link_path);
        }
    }

    // --- 論理正規化テスト ---

    #[test]
    fn test_logical_normalize_parent_dir() {
        let result = logical_normalize(Path::new("/home/user/../../etc"));
        assert_eq!(result, PathBuf::from("/etc"));
    }

    #[test]
    fn test_logical_normalize_cur_dir() {
        let result = logical_normalize(Path::new("/home/user/./projects"));
        assert_eq!(result, PathBuf::from("/home/user/projects"));
    }

    #[test]
    fn test_logical_normalize_root_overflow() {
        // ルートを超える .. は無視
        let result = logical_normalize(Path::new("/../../etc"));
        assert_eq!(result, PathBuf::from("/etc"));
    }

    #[test]
    fn test_logical_normalize_multiple_dots() {
        let result = logical_normalize(Path::new("/a/b/../c/./d/../e"));
        assert_eq!(result, PathBuf::from("/a/c/e"));
    }
}
