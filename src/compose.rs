use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::docker_args::{BindMount, DangerousFlag, MountSource};
use crate::error::{Result, SafeDockerError};

/// Compose ファイルの解析結果
#[derive(Debug, Default)]
pub struct ComposeAnalysis {
    pub bind_mounts: Vec<BindMount>,
    pub dangerous_flags: Vec<DangerousFlag>,
}

/// docker-compose.yml からバインドマウントを抽出する
pub fn extract_bind_mounts(compose_path: &Path) -> Result<Vec<BindMount>> {
    let analysis = analyze_compose(compose_path)?;
    Ok(analysis.bind_mounts)
}

/// docker-compose.yml を総合的に解析する（マウント + 危険設定）
pub fn analyze_compose(compose_path: &Path) -> Result<ComposeAnalysis> {
    let content = std::fs::read_to_string(compose_path).map_err(|e| {
        SafeDockerError::ComposeParse(format!(
            "Cannot read compose file {:?}: {}",
            compose_path, e
        ))
    })?;

    // .env ファイルを読み込んで変数を展開
    let env_vars = load_env_file(compose_path.parent().unwrap_or(Path::new(".")));

    let expanded = expand_variables(&content, &env_vars);

    let yaml: serde_yml::Value = serde_yml::from_str(&expanded).map_err(|e| {
        SafeDockerError::ComposeParse(format!(
            "Cannot parse compose file {:?}: {}",
            compose_path, e
        ))
    })?;

    let mut analysis = ComposeAnalysis::default();
    let compose_dir = compose_path
        .parent()
        .unwrap_or(Path::new("."))
        .to_path_buf();

    // services セクション解析
    if let Some(services) = yaml.get("services").and_then(|s| s.as_mapping()) {
        for (_service_name, service) in services {
            extract_service_volumes(service, &compose_dir, &mut analysis.bind_mounts);
            extract_service_dangerous_settings(service, &mut analysis.dangerous_flags);
        }
    }

    Ok(analysis)
}

/// サービス定義から volumes を抽出
fn extract_service_volumes(
    service: &serde_yml::Value,
    compose_dir: &Path,
    mounts: &mut Vec<BindMount>,
) {
    let Some(volumes) = service.get("volumes").and_then(|v| v.as_sequence()) else {
        return;
    };

    for volume in volumes {
        match volume {
            // Short syntax: "host:container[:opts]"
            serde_yml::Value::String(s) => {
                if let Some(bm) = parse_short_volume(s, compose_dir) {
                    mounts.push(bm);
                }
            }
            // Long syntax: { type: bind, source: ..., target: ... }
            serde_yml::Value::Mapping(m) => {
                if let Some(bm) = parse_long_volume(m, compose_dir) {
                    mounts.push(bm);
                }
            }
            _ => {}
        }
    }

    // driver_opts.device によるバインドマウント偽装の検出
    if let Some(seq) = service.get("volumes").and_then(|v| v.as_sequence()) {
        for vol in seq {
            if let Some(mapping) = vol.as_mapping()
                && let Some(device) = mapping
                    .get(serde_yml::Value::String("driver_opts".to_string()))
                    .and_then(|d| d.as_mapping())
                    .and_then(|driver_opts| {
                        driver_opts
                            .get(serde_yml::Value::String("device".to_string()))
                            .and_then(|d| d.as_str())
                    })
                && (device.starts_with('/') || device.starts_with('.'))
            {
                mounts.push(BindMount {
                    host_path: resolve_path(device, compose_dir),
                    container_path: String::new(),
                    source: MountSource::ComposeVolumes,
                    read_only: false,
                });
            }
        }
    }
}

/// サービス定義から危険な設定を抽出
fn extract_service_dangerous_settings(service: &serde_yml::Value, flags: &mut Vec<DangerousFlag>) {
    // privileged: true
    if service
        .get("privileged")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        flags.push(DangerousFlag::Privileged);
    }

    // network_mode: host | container:NAME | service:NAME
    if let Some(mode) = service.get("network_mode").and_then(|v| v.as_str()) {
        if mode == "host" {
            flags.push(DangerousFlag::NetworkHost);
        } else if let Some(name) = mode
            .strip_prefix("container:")
            .or_else(|| mode.strip_prefix("service:"))
        {
            flags.push(DangerousFlag::NetworkContainer(name.to_string()));
        }
    }

    // pid: host | container:NAME | service:NAME
    if let Some(pid) = service.get("pid").and_then(|v| v.as_str()) {
        if pid == "host" {
            flags.push(DangerousFlag::PidHost);
        } else if let Some(name) = pid
            .strip_prefix("container:")
            .or_else(|| pid.strip_prefix("service:"))
        {
            flags.push(DangerousFlag::PidContainer(name.to_string()));
        }
    }

    // userns_mode: host
    if let Some(mode) = service.get("userns_mode").and_then(|v| v.as_str())
        && mode == "host"
    {
        flags.push(DangerousFlag::UsernsHost);
    }

    // ipc: host | container:NAME | service:NAME
    if let Some(ipc) = service.get("ipc").and_then(|v| v.as_str()) {
        if ipc == "host" {
            flags.push(DangerousFlag::IpcHost);
        } else if let Some(name) = ipc
            .strip_prefix("container:")
            .or_else(|| ipc.strip_prefix("service:"))
        {
            flags.push(DangerousFlag::IpcContainer(name.to_string()));
        }
    }

    // uts: host
    if let Some(uts) = service.get("uts").and_then(|v| v.as_str())
        && uts == "host"
    {
        flags.push(DangerousFlag::UtsHost);
    }

    // cap_add: [SYS_ADMIN, ...]
    if let Some(caps) = service.get("cap_add").and_then(|v| v.as_sequence()) {
        for cap in caps {
            if let Some(cap_str) = cap.as_str() {
                flags.push(DangerousFlag::CapAdd(cap_str.to_string()));
            }
        }
    }

    // security_opt: [apparmor:unconfined, seccomp:unconfined, ...]
    if let Some(opts) = service.get("security_opt").and_then(|v| v.as_sequence()) {
        for opt in opts {
            if let Some(opt_str) = opt.as_str() {
                flags.push(DangerousFlag::SecurityOpt(opt_str.to_string()));
            }
        }
    }

    // devices: [/dev/sda, ...]
    if let Some(devices) = service.get("devices").and_then(|v| v.as_sequence()) {
        for device in devices {
            if let Some(dev_str) = device.as_str() {
                flags.push(DangerousFlag::Device(dev_str.to_string()));
            }
        }
    }
}

/// Short syntax のボリュームをパース: "host:container[:opts]"
fn parse_short_volume(volume_str: &str, compose_dir: &Path) -> Option<BindMount> {
    let parts: Vec<&str> = volume_str.splitn(3, ':').collect();
    if parts.len() < 2 {
        return None;
    }

    let host = parts[0];

    // 名前付きボリュームはスキップ
    if !host.starts_with('/')
        && !host.starts_with('.')
        && !host.starts_with('~')
        && !host.starts_with('$')
    {
        return None;
    }

    let read_only = parts
        .get(2)
        .is_some_and(|opts| opts.split(',').any(|o| o == "ro"));

    Some(BindMount {
        host_path: resolve_path(host, compose_dir),
        container_path: parts[1].to_string(),
        source: MountSource::ComposeVolumes,
        read_only,
    })
}

/// Long syntax のボリュームをパース
fn parse_long_volume(mapping: &serde_yml::Mapping, compose_dir: &Path) -> Option<BindMount> {
    let volume_type = mapping
        .get(serde_yml::Value::String("type".to_string()))
        .and_then(|v| v.as_str())
        .unwrap_or("volume");

    if volume_type != "bind" {
        return None;
    }

    let source = mapping
        .get(serde_yml::Value::String("source".to_string()))
        .and_then(|v| v.as_str())?;

    let target = mapping
        .get(serde_yml::Value::String("target".to_string()))
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let read_only = mapping
        .get(serde_yml::Value::String("read_only".to_string()))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    Some(BindMount {
        host_path: resolve_path(source, compose_dir),
        container_path: target.to_string(),
        source: MountSource::ComposeVolumes,
        read_only,
    })
}

/// 相対パスを compose ファイルのディレクトリを基準に解決
fn resolve_path(path: &str, compose_dir: &Path) -> String {
    if path.starts_with('/') || path.starts_with('~') || path.starts_with('$') {
        return path.to_string();
    }

    // 相対パスを compose_dir を基準に解決
    compose_dir.join(path).to_string_lossy().to_string()
}

/// .env ファイルを読み込む
fn load_env_file(dir: &Path) -> HashMap<String, String> {
    let mut vars = HashMap::new();

    // まず環境変数を取得
    for (key, value) in std::env::vars() {
        vars.insert(key, value);
    }

    // .env ファイルで上書き
    let env_path = dir.join(".env");
    if let Ok(content) = std::fs::read_to_string(&env_path) {
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim().trim_matches('"').trim_matches('\'');
                vars.insert(key.to_string(), value.to_string());
            }
        }
    }

    vars
}

/// compose ファイル内の変数 (${VAR} / $VAR) を展開する
fn expand_variables(content: &str, vars: &HashMap<String, String>) -> String {
    let mut result = String::with_capacity(content.len());
    let mut chars = content.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '$' {
            if chars.peek() == Some(&'{') {
                chars.next(); // '{' を消費
                // まず '}' までを全部読み取る
                let mut inner = String::new();
                for c in chars.by_ref() {
                    if c == '}' {
                        break;
                    }
                    inner.push(c);
                }

                // ${VAR:-default} のパース
                let (var_name, default_value) = if let Some(pos) = inner.find(":-") {
                    (inner[..pos].to_string(), Some(inner[pos + 2..].to_string()))
                } else {
                    (inner, None)
                };

                if let Some(value) = vars.get(&var_name) {
                    result.push_str(value);
                } else if let Some(default) = default_value {
                    result.push_str(&default);
                }
            } else if chars
                .peek()
                .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
            {
                let mut var_name = String::new();
                while chars
                    .peek()
                    .is_some_and(|c| c.is_ascii_alphanumeric() || *c == '_')
                {
                    var_name.push(chars.next().unwrap());
                }
                if let Some(value) = vars.get(&var_name) {
                    result.push_str(value);
                }
            } else {
                result.push(ch);
            }
        } else {
            result.push(ch);
        }
    }

    result
}

/// compose ファイルのパスを解決する
/// docker compose -f で指定されたパス、または cwd からデフォルトパスを探す
pub fn find_compose_file(specified_file: Option<&str>, cwd: &str) -> Option<PathBuf> {
    if let Some(file) = specified_file {
        let path = Path::new(file);
        if path.is_absolute() {
            return Some(path.to_path_buf());
        }
        return Some(Path::new(cwd).join(file));
    }

    // デフォルトの compose ファイルを探す
    let candidates = [
        "compose.yml",
        "compose.yaml",
        "docker-compose.yml",
        "docker-compose.yaml",
    ];

    for candidate in &candidates {
        let path = Path::new(cwd).join(candidate);
        if path.exists() {
            return Some(path);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_variables() {
        let mut vars = HashMap::new();
        vars.insert("HOME".to_string(), "/home/user".to_string());
        vars.insert("APP_DIR".to_string(), "/opt/app".to_string());

        assert_eq!(expand_variables("${HOME}/data", &vars), "/home/user/data");
        assert_eq!(expand_variables("$HOME/data", &vars), "/home/user/data");
        assert_eq!(expand_variables("${MISSING:-/default}", &vars), "/default");
        assert_eq!(expand_variables("no vars here", &vars), "no vars here");
    }

    #[test]
    fn test_parse_short_volume_absolute() {
        let bm = parse_short_volume("/host:/container", Path::new("/project")).unwrap();
        assert_eq!(bm.host_path, "/host");
        assert_eq!(bm.container_path, "/container");
    }

    #[test]
    fn test_parse_short_volume_relative() {
        let bm = parse_short_volume("./src:/app/src", Path::new("/project")).unwrap();
        assert_eq!(bm.host_path, "/project/./src");
    }

    #[test]
    fn test_parse_short_volume_named() {
        assert!(parse_short_volume("myvolume:/data", Path::new("/project")).is_none());
    }

    #[test]
    fn test_parse_compose_yaml() {
        let yaml_str = r#"
services:
  web:
    volumes:
      - ./src:/app/src
      - /etc/config:/config:ro
      - type: bind
        source: /host/data
        target: /container/data
        read_only: true
      - named_volume:/data
"#;
        let dir = tempfile::tempdir().unwrap();
        let compose_path = dir.path().join("docker-compose.yml");
        std::fs::write(&compose_path, yaml_str).unwrap();

        let mounts = extract_bind_mounts(&compose_path).unwrap();
        // named_volume はスキップされるので3つ
        assert_eq!(mounts.len(), 3);

        // ./src は compose_dir 基準に解決
        assert!(mounts[0].host_path.ends_with("/./src"));
        assert_eq!(mounts[0].container_path, "/app/src");

        assert_eq!(mounts[1].host_path, "/etc/config");
        assert!(mounts[1].read_only);

        assert_eq!(mounts[2].host_path, "/host/data");
        assert!(mounts[2].read_only);
    }

    #[test]
    fn test_find_compose_file_specified() {
        let dir = tempfile::tempdir().unwrap();
        let path = find_compose_file(Some("custom.yml"), dir.path().to_str().unwrap());
        assert!(path.is_some());
        assert!(path.unwrap().ends_with("custom.yml"));
    }

    #[test]
    fn test_find_compose_file_default() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("docker-compose.yml"), "version: '3'").unwrap();
        let path = find_compose_file(None, dir.path().to_str().unwrap());
        assert!(path.is_some());
        assert!(
            path.unwrap()
                .to_str()
                .unwrap()
                .ends_with("docker-compose.yml")
        );
    }

    #[test]
    fn test_find_compose_file_none() {
        let dir = tempfile::tempdir().unwrap();
        let path = find_compose_file(None, dir.path().to_str().unwrap());
        assert!(path.is_none());
    }

    #[test]
    fn test_load_env_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".env"),
            "APP_PORT=8080\nAPP_NAME=\"myapp\"\n# comment\n",
        )
        .unwrap();
        let vars = load_env_file(dir.path());
        assert_eq!(vars.get("APP_PORT").unwrap(), "8080");
        assert_eq!(vars.get("APP_NAME").unwrap(), "myapp");
    }

    // --- Compose 網羅テスト ---

    #[test]
    fn test_parse_multiple_services_volumes() {
        let yaml_str = r#"
services:
  web:
    volumes:
      - ./web:/app
  db:
    volumes:
      - /data/db:/var/lib/mysql
  cache:
    volumes:
      - cache_vol:/data
"#;
        let dir = tempfile::tempdir().unwrap();
        let compose_path = dir.path().join("compose.yml");
        std::fs::write(&compose_path, yaml_str).unwrap();

        let mounts = extract_bind_mounts(&compose_path).unwrap();
        // cache_vol は名前付きボリュームなのでスキップ
        assert_eq!(mounts.len(), 2);
        assert!(mounts[0].host_path.ends_with("/./web"));
        assert_eq!(mounts[1].host_path, "/data/db");
    }

    #[test]
    fn test_parse_env_file_variable_expansion() {
        let yaml_str = r#"
services:
  web:
    volumes:
      - ${DATA_DIR}:/data
"#;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), "DATA_DIR=/opt/data\n").unwrap();
        let compose_path = dir.path().join("compose.yml");
        std::fs::write(&compose_path, yaml_str).unwrap();

        let mounts = extract_bind_mounts(&compose_path).unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].host_path, "/opt/data");
    }

    #[test]
    fn test_parse_driver_opts_device() {
        let yaml_str = r#"
services:
  web:
    volumes:
      - type: volume
        source: mydata
        target: /data
        driver_opts:
          device: /host/path
"#;
        let dir = tempfile::tempdir().unwrap();
        let compose_path = dir.path().join("compose.yml");
        std::fs::write(&compose_path, yaml_str).unwrap();

        let mounts = extract_bind_mounts(&compose_path).unwrap();
        // driver_opts.device でバインドマウント偽装を検出
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].host_path, "/host/path");
    }

    #[test]
    fn test_parse_empty_services() {
        let yaml_str = r#"
services:
"#;
        let dir = tempfile::tempdir().unwrap();
        let compose_path = dir.path().join("compose.yml");
        std::fs::write(&compose_path, yaml_str).unwrap();

        let mounts = extract_bind_mounts(&compose_path).unwrap();
        assert!(mounts.is_empty());
    }

    #[test]
    fn test_parse_no_services_key() {
        let yaml_str = r#"
version: '3'
"#;
        let dir = tempfile::tempdir().unwrap();
        let compose_path = dir.path().join("compose.yml");
        std::fs::write(&compose_path, yaml_str).unwrap();

        let mounts = extract_bind_mounts(&compose_path).unwrap();
        assert!(mounts.is_empty());
    }

    #[test]
    fn test_parse_invalid_yaml() {
        let dir = tempfile::tempdir().unwrap();
        let compose_path = dir.path().join("compose.yml");
        // YAML パースエラーになる文字列
        std::fs::write(&compose_path, ":\n  - :\n  a: [b\n").unwrap();

        let result = extract_bind_mounts(&compose_path);
        assert!(result.is_err(), "Invalid YAML should return error");
    }

    #[test]
    fn test_expand_variable_with_default_present() {
        let mut vars = HashMap::new();
        vars.insert("MY_VAR".to_string(), "/actual/path".to_string());

        let result = expand_variables("${MY_VAR:-/default/path}", &vars);
        assert_eq!(result, "/actual/path");
    }

    #[test]
    fn test_expand_variable_with_default_absent() {
        let vars = HashMap::new();

        let result = expand_variables("${MISSING:-/default/path}", &vars);
        assert_eq!(result, "/default/path");
    }

    #[test]
    fn test_parse_long_volume_type_omitted() {
        // type 省略 → デフォルト "volume" → バインドマウントではない
        let yaml_str = r#"
services:
  web:
    volumes:
      - source: /host/data
        target: /data
"#;
        let dir = tempfile::tempdir().unwrap();
        let compose_path = dir.path().join("compose.yml");
        std::fs::write(&compose_path, yaml_str).unwrap();

        let mounts = extract_bind_mounts(&compose_path).unwrap();
        // type 省略 = volume → スキップされるべき
        // ただし driver_opts.device 検出はされうる
        let bind_only: Vec<_> = mounts
            .iter()
            .filter(|m| m.host_path == "/host/data")
            .collect();
        assert!(
            bind_only.is_empty(),
            "long syntax without type=bind should be skipped"
        );
    }

    #[test]
    fn test_parse_long_volume_read_only_default() {
        let yaml_str = r#"
services:
  web:
    volumes:
      - type: bind
        source: /host/data
        target: /data
"#;
        let dir = tempfile::tempdir().unwrap();
        let compose_path = dir.path().join("compose.yml");
        std::fs::write(&compose_path, yaml_str).unwrap();

        let mounts = extract_bind_mounts(&compose_path).unwrap();
        assert_eq!(mounts.len(), 1);
        assert!(!mounts[0].read_only, "read_only should default to false");
    }

    #[test]
    fn test_parse_relative_volume_compose_dir() {
        let yaml_str = r#"
services:
  web:
    volumes:
      - ./data:/app/data
"#;
        let dir = tempfile::tempdir().unwrap();
        let compose_path = dir.path().join("compose.yml");
        std::fs::write(&compose_path, yaml_str).unwrap();

        let mounts = extract_bind_mounts(&compose_path).unwrap();
        assert_eq!(mounts.len(), 1);
        // compose_dir を基準に解決される
        let expected_prefix = dir.path().to_string_lossy().to_string();
        assert!(
            mounts[0].host_path.starts_with(&expected_prefix),
            "Relative path should be resolved relative to compose dir: {}",
            mounts[0].host_path
        );
    }

    #[test]
    fn test_find_compose_file_relative() {
        let dir = tempfile::tempdir().unwrap();
        // ../compose.yml パターン
        let result = find_compose_file(Some("../compose.yml"), dir.path().to_str().unwrap());
        assert!(result.is_some());
        let path = result.unwrap();
        assert!(path.to_string_lossy().contains("../compose.yml"));
    }

    #[test]
    fn test_expand_variables_dollar_number() {
        let vars = HashMap::new();
        // $5 — '5' は数字なので変数名扱いされない (alphanumeric||_) → 実装依存
        // 現状の実装では $5 は変数展開を試みる ($の後に alphanumeric がある)
        // → "5" で検索 → 見つからない → 空文字列
        let result = expand_variables("price is $5", &vars);
        // 実装の動作に合わせて検証
        assert_eq!(result, "price is ");
    }

    #[test]
    fn test_expand_variables_empty_braces() {
        let vars = HashMap::new();
        let result = expand_variables("${}", &vars);
        // 空の変数名は展開されない (空文字列として)
        assert_eq!(result, "");
    }

    #[test]
    fn test_parse_compose_nonexistent_file() {
        let result = extract_bind_mounts(std::path::Path::new("/nonexistent/compose.yml"));
        assert!(result.is_err());
    }
}
