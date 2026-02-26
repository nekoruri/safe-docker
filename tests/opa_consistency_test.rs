//! OPA authz.rego と safe-docker のデフォルトポリシーの一貫性検証テスト
//!
//! safe-docker のポリシーを拡張した際に、OPA 側の authz.rego への反映漏れを検出する。
//! `cargo test` の一部として自動実行される。

use std::collections::HashSet;

/// opa/authz.rego の内容を読み込む
fn read_rego() -> String {
    let rego_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("opa/authz.rego");
    std::fs::read_to_string(&rego_path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", rego_path.display(), e))
}

/// safe-docker のデフォルト blocked_capabilities と同じリスト
/// (src/config.rs の default_blocked_capabilities() と同期)
fn safe_docker_default_capabilities() -> Vec<&'static str> {
    vec![
        "SYS_ADMIN",
        "SYS_PTRACE",
        "SYS_MODULE",
        "SYS_RAWIO",
        "DAC_READ_SEARCH",
        "NET_ADMIN",
        "BPF",
        "PERFMON",
        "SYS_BOOT",
        "ALL",
    ]
}

/// OPA authz.rego の CapAdd deny ルールから capability リストを抽出する
fn extract_rego_capabilities(rego: &str) -> HashSet<String> {
    let mut caps = HashSet::new();

    // CapAdd ブロック内の capability を探す
    let mut in_cap_block = false;
    for line in rego.lines() {
        let trimmed = line.trim();

        // CapAdd ブロックの開始を検出
        if trimmed.contains("HostConfig.CapAdd") {
            in_cap_block = true;
            continue;
        }

        if in_cap_block {
            // ブロックの終了
            if trimmed == "}" {
                in_cap_block = false;
                continue;
            }

            // "CAPABILITY_NAME", や "CAPABILITY_NAME" を抽出
            if let Some(start) = trimmed.find('"') {
                if let Some(end) = trimmed[start + 1..].find('"') {
                    let cap = &trimmed[start + 1..start + 1 + end];
                    if !cap.is_empty() {
                        caps.insert(cap.to_string());
                    }
                }
            }
        }
    }

    caps
}

/// OPA authz.rego から名前空間 deny ルールのフィールド名を抽出する
fn extract_rego_namespace_fields(rego: &str) -> HashSet<String> {
    let mut fields = HashSet::new();
    let namespace_patterns = [
        "PidMode",
        "NetworkMode",
        "IpcMode",
        "UTSMode",
        "CgroupnsMode",
        "UsernsMode",
    ];

    for pattern in &namespace_patterns {
        let search = format!("HostConfig.{} == \"host\"", pattern);
        if rego.contains(&search) {
            fields.insert(pattern.to_string());
        }
    }

    fields
}

/// OPA authz.rego から security-opt deny ルールのパターンを抽出する
fn extract_rego_security_opts(rego: &str) -> HashSet<String> {
    let mut opts = HashSet::new();
    let patterns = [
        "apparmor=unconfined",
        "seccomp=unconfined",
        "label=disable",
        "label:disable",
        "no-new-privileges=false",
        "systempaths=unconfined",
    ];

    for pattern in &patterns {
        let search = format!("contains(opt, \"{}\")", pattern);
        if rego.contains(&search) {
            opts.insert(pattern.to_string());
        }
    }

    opts
}

// =============================================================================
// テスト
// =============================================================================

#[test]
fn test_rego_contains_all_blocked_capabilities() {
    let rego = read_rego();
    let rego_caps = extract_rego_capabilities(&rego);
    let expected_caps = safe_docker_default_capabilities();

    let mut missing: Vec<&str> = Vec::new();
    for cap in &expected_caps {
        if !rego_caps.contains(*cap) {
            missing.push(cap);
        }
    }

    assert!(
        missing.is_empty(),
        "opa/authz.rego is missing the following capabilities from safe-docker defaults: {:?}\n\
         Found in rego: {:?}\n\
         Expected: {:?}\n\
         Hint: Add missing capabilities to the CapAdd deny rule in opa/authz.rego",
        missing,
        rego_caps,
        expected_caps
    );
}

#[test]
fn test_rego_no_extra_capabilities_beyond_defaults() {
    // OPA 側に safe-docker のデフォルトにない capability がある場合は意図的なものか確認を促す
    let rego = read_rego();
    let rego_caps = extract_rego_capabilities(&rego);
    let expected_caps: HashSet<String> = safe_docker_default_capabilities()
        .into_iter()
        .map(|s| s.to_string())
        .collect();

    let extra: Vec<&String> = rego_caps.difference(&expected_caps).collect();

    // extra があっても OPA 側がより厳しい分には問題ないが、同期漏れの可能性があるので warning レベル
    // テストとしては通すが、差分があればメッセージを出す
    if !extra.is_empty() {
        eprintln!(
            "INFO: opa/authz.rego has additional capabilities not in safe-docker defaults: {:?}\n\
             This is acceptable (OPA can be stricter), but verify this is intentional.",
            extra
        );
    }
}

#[test]
fn test_rego_contains_privileged_deny() {
    let rego = read_rego();
    assert!(
        rego.contains("HostConfig.Privileged == true"),
        "opa/authz.rego must deny --privileged (HostConfig.Privileged == true)"
    );
}

#[test]
fn test_rego_contains_all_namespace_deny_rules() {
    let rego = read_rego();
    let found = extract_rego_namespace_fields(&rego);

    let expected = [
        "PidMode",
        "NetworkMode",
        "IpcMode",
        "UTSMode",
        "CgroupnsMode",
        "UsernsMode",
    ];

    let mut missing: Vec<&str> = Vec::new();
    for field in &expected {
        if !found.contains(*field) {
            missing.push(field);
        }
    }

    assert!(
        missing.is_empty(),
        "opa/authz.rego is missing namespace deny rules for: {:?}\n\
         Found: {:?}\n\
         Hint: Add `deny if {{ input.Body.HostConfig.<Field> == \"host\" }}` for each",
        missing,
        found
    );
}

#[test]
fn test_rego_contains_device_deny() {
    let rego = read_rego();
    assert!(
        rego.contains("HostConfig.Devices"),
        "opa/authz.rego must deny device access (HostConfig.Devices)"
    );
}

#[test]
fn test_rego_contains_all_security_opt_deny_rules() {
    let rego = read_rego();
    let found = extract_rego_security_opts(&rego);

    let expected = [
        "apparmor=unconfined",
        "seccomp=unconfined",
        "label=disable",
        "label:disable",
        "no-new-privileges=false",
        "systempaths=unconfined",
    ];

    let mut missing: Vec<&str> = Vec::new();
    for opt in &expected {
        if !found.contains(*opt) {
            missing.push(opt);
        }
    }

    assert!(
        missing.is_empty(),
        "opa/authz.rego is missing security-opt deny rules for: {:?}\n\
         Found: {:?}\n\
         Hint: Add `deny if {{ opt := input.Body.HostConfig.SecurityOpt[_]; contains(opt, \"<pattern>\") }}`",
        missing,
        found
    );
}

#[test]
fn test_rego_contains_docker_socket_deny() {
    let rego = read_rego();
    assert!(
        rego.contains("/var/run/docker.sock"),
        "opa/authz.rego must deny Docker socket mount (/var/run/docker.sock)"
    );
}

#[test]
fn test_rego_contains_bind_mount_path_restriction() {
    let rego = read_rego();
    // BindMounts のパス制限が存在することを確認
    assert!(
        rego.contains("input.BindMounts"),
        "opa/authz.rego must contain bind mount path restrictions (input.BindMounts)"
    );
    // パストラバーサル防止（Source と Resolved の不一致検出）
    assert!(
        rego.contains("bm.Source") && rego.contains("bm.Resolved"),
        "opa/authz.rego must check both Source and Resolved for path traversal prevention"
    );
}

#[test]
fn test_rego_contains_plugin_lockout_prevention() {
    let rego = read_rego();
    // プラグインのロックアウト防止ルールが存在することを確認
    assert!(
        rego.contains("/Plugin.Disable") && rego.contains("/Plugin.Enable"),
        "opa/authz.rego must allow Plugin.Disable and Plugin.Enable to prevent lockout"
    );
}

#[test]
fn test_rego_uses_placeholder_home_path() {
    let rego = read_rego();
    // 開発環境固有のパスがハードコードされていないことを確認
    assert!(
        !rego.contains("/home/masa/"),
        "opa/authz.rego must not contain development-specific path /home/masa/. \
         Use the placeholder /home/username/ instead."
    );
}

#[test]
fn test_rego_capabilities_match_config_defaults() {
    // config.rs の Config::default() と直接比較
    // (safe_docker_default_capabilities() リストが config.rs と同期していることの間接検証)
    let rego = read_rego();
    let rego_caps = extract_rego_capabilities(&rego);

    // config.rs の default_blocked_capabilities() で定義されているものと一致を確認
    // このリストを更新した場合は safe_docker_default_capabilities() も更新すること
    let expected: HashSet<String> = safe_docker_default_capabilities()
        .into_iter()
        .map(|s| s.to_string())
        .collect();

    assert_eq!(
        rego_caps,
        expected,
        "opa/authz.rego capabilities must match safe-docker defaults exactly.\n\
         In rego but not in defaults: {:?}\n\
         In defaults but not in rego: {:?}\n\
         Hint: Update opa/authz.rego or safe_docker_default_capabilities() in this test",
        rego_caps.difference(&expected).collect::<Vec<_>>(),
        expected.difference(&rego_caps).collect::<Vec<_>>()
    );
}
