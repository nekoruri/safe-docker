# コントリビューションガイド

safe-docker はセキュリティツールのため、変更の手順漏れがそのまま検出漏れにつながります。
このガイドでは、よくある変更パターンごとに必要な手順をまとめています。

## 開発環境のセットアップ

```bash
# pre-commit hook の有効化（cargo fmt を自動チェック）
git config core.hooksPath scripts
# スクリプトに実行権限を付与（"permission denied" エラーが出る場合）
chmod +x scripts/pre-commit

# ビルド
cargo build --release

# 全テスト実行
cargo test

# 静的解析（警告をエラー扱い）
cargo clippy -- -D warnings

# ベンチマーク
cargo bench
```

## PR の作り方

1. `main` から feature ブランチを作成
2. 変更を実装し、テストを追加
3. `cargo test` と `cargo clippy -- -D warnings` が通ることを確認
4. PR を作成（直接 `main` にプッシュしない）

## テストの書き方

| テスト種別 | ファイル | 用途 |
|-----------|---------|------|
| ユニットテスト | 各 `src/*.rs` 内の `#[cfg(test)] mod tests` | 関数単位の検証 |
| 統合テスト (Hook) | `tests/integration_test.rs` | バイナリを起動し stdin/stdout で E2E 検証 |
| 統合テスト (Wrapper) | `tests/wrapper_test.rs` | `/bin/echo` をモック docker として E2E 検証 |
| セキュリティテスト | `tests/security_test.rs` | バイパスパターンの検出検証 |
| ファジング | `tests/proptest_test.rs` | ランダム入力によるクラッシュ耐性 |

`DockerCommand` をテスト内で構築する際は `host_paths: vec![]` を忘れないこと。

---

## 新しい危険フラグの追加チェックリスト

Docker に新しい危険なフラグ（例: `--privileged`、`--cap-add` のような）を検出対象に追加する際の手順です。

### チェックリスト

- [ ] **`DangerousFlag` enum にバリアントを追加** (`src/docker_args.rs`)
  ```rust
  pub enum DangerousFlag {
      // ... 既存バリアント ...
      /// 新しいフラグの説明
      NewFlag(String),
  }
  ```
- [ ] **`Display` 実装を追加** (`src/docker_args.rs` の `impl std::fmt::Display for DangerousFlag`)
  ```rust
  DangerousFlag::NewFlag(val) => write!(f, "--new-flag {}", val),
  ```
- [ ] **`parse_docker_args()` で検出ロジックを追加** (`src/docker_args.rs`)
  - `--flag VALUE` 形式（スペース区切り）と `--flag=VALUE` 形式（`=` 区切り）の両方を処理する
  ```rust
  // --new-flag
  if arg == "--new-flag" {
      if i + 1 < args.len() {
          cmd.dangerous_flags.push(DangerousFlag::NewFlag(args[i + 1].to_string()));
          i += 2;
          continue;
      }
  } else if let Some(value) = arg.strip_prefix("--new-flag=") {
      cmd.dangerous_flags.push(DangerousFlag::NewFlag(value.to_string()));
      i += 1;
      continue;
  }
  ```
- [ ] **`is_flag_with_value()` への追加**（値を取るフラグの場合。詳細は後述）
- [ ] **`policy.rs` の `evaluate()` で deny/ask/allow の判定を追加** (`src/policy.rs`)
  ```rust
  DangerousFlag::NewFlag(val) => {
      deny_reasons.push(format!("--new-flag={} is not allowed (理由)", val));
  }
  ```
- [ ] **Compose 対応**（該当する場合: `src/compose.rs` の `extract_service_dangerous_settings()`）
  - Docker CLI フラグに対応する Compose YAML キーがあれば検出ロジックを追加する
  - 例: `--pid=host` に対する `pid: host`、`--cap-add` に対する `cap_add:`
- [ ] **設定ファイル対応**（該当する場合: `src/config.rs`）
  - `blocked_flags` や `blocked_capabilities` のデフォルトリストへの追加を検討する
- [ ] **ユニットテスト追加** (`src/docker_args.rs` の `mod tests`)
  - `=` 形式とスペース区切り形式の両方をテストする
- [ ] **統合テスト追加** (`tests/wrapper_test.rs`)
  - 実際のバイナリ実行で deny/ask されることを検証する
- [ ] **セキュリティテスト追加** (`tests/security_test.rs`)
  - バイパスパターンがないことを検証する
- [ ] **`docs/ATTACK_SURFACE_ANALYSIS.md` の更新**
  - 新しい攻撃面の記述を追加する

### 処理フローの確認

新しい危険フラグがどう処理されるかの全体像:

```
CLI 引数 / stdin JSON
  → docker_args::parse_docker_args()   # DangerousFlag に変換
  → policy::evaluate()                 # deny/ask/allow を判定
  → Decision として返却               # Hook: stdout JSON / Wrapper: exit code
```

Compose 経由の場合:
```
compose.yml
  → compose::extract_service_dangerous_settings()  # DangerousFlag に変換
  → policy::evaluate()                             # deny/ask/allow を判定
```

---

## `is_flag_with_value()` リスト更新ガイド

### この関数の目的

`src/docker_args.rs` の `is_flag_with_value()` は、**値を取る（次の引数を消費する）フラグの一覧**です。`parse_docker_args()` のメインループで、個別処理されなかったフラグについて「次の引数はフラグの値であり、イメージ名やサブコマンドではない」と判断するために使います。

### なぜ重要か

このリストに不足があると、以下の誤認が連鎖的に発生します:

```
docker run --some-flag its-value --privileged ubuntu
                       ^^^^^^^^
                       is_flag_with_value() にないと
                       これがイメージ名と誤認される
                       → --privileged が検出されない
```

つまり、**リストの不足 = 危険フラグの検出漏れ**につながります。

### 現在のリスト

2026-02 時点で以下のフラグが登録されています:

```
-e / --env, --name, -w / --workdir, -p / --publish, --expose,
-l / --label, --hostname / -h, --user / -u, --entrypoint,
--restart, --memory / -m, --cpus, --log-driver, --log-opt,
--network / --net, --ip, --dns, --add-host, --tmpfs, --shm-size,
--ulimit, --stop-signal, --stop-timeout, --health-cmd,
--health-interval, --health-retries, --health-start-period,
--health-timeout, --platform, --pull, --cgroupns, --ipc,
--userns, --uts, --pid, --volumes-from, --runtime,
--cgroup-parent, --cidfile, --mac-address, --network-alias,
--storage-opt, --sysctl, --gpus, --attach / -a, --link,
--volume-driver, --env-file, --label-file, --device-cgroup-rule,
--device-read-bps, --device-write-bps, --device-read-iops,
--device-write-iops, --blkio-weight, --blkio-weight-device,
-c / --cpu-shares, --cpuset-cpus, --cpuset-mems, --cpu-period,
--cpu-quota, --memory-swap, --memory-swappiness,
--memory-reservation, --kernel-memory, --pids-limit,
--group-add, --domainname, --oom-score-adj, --isolation,
--ip6, --dns-search, --dns-option
```

### 追加手順

1. Docker 公式ドキュメントで該当フラグが値を取ることを確認する
2. `is_flag_with_value()` の `matches!` マクロにフラグ名を追加する
   ```rust
   fn is_flag_with_value(arg: &str) -> bool {
       matches!(
           arg,
           // ... 既存フラグ ...
               | "--new-option"  // 追加
       )
   }
   ```
3. **個別に検出処理を書いたフラグでも、このリストにも追加する**こと。理由: 個別処理は `--flag=value` 形式の `=` 付きだけ先にマッチし、`--flag value` 形式は `is_flag_with_value()` でのスキップに頼るケースがあるため

### 追加が不要なケース

- ブーリアンフラグ（値を取らない）: `--privileged`, `--rm`, `--detach` など
- `parse_docker_args()` で個別に値を消費済みで、かつスペース区切り形式も処理しているフラグ
  - ただし安全のため、リストへの追加を推奨する（重複しても害はない）

---

## 新しいホストパス検証の追加

Docker がホスト上のファイルを読み取るフラグ（例: `--env-file`, `--label-file`）を追加する場合:

1. `parse_docker_args()` でパスを `cmd.host_paths` に追加する
2. `policy::evaluate()` が `host_paths` を自動的に検証するため、policy 側の変更は通常不要
3. Compose YAML に対応するキーがあれば `compose.rs` でも抽出する

```rust
// docker_args.rs の parse_docker_args() 内
if arg == "--new-file-flag" {
    if i + 1 < args.len() {
        cmd.host_paths.push(args[i + 1].to_string());
        i += 2;
        continue;
    }
} else if let Some(value) = arg.strip_prefix("--new-file-flag=") {
    cmd.host_paths.push(value.to_string());
    i += 1;
    continue;
}
```

---

## Compose YAML 設定の追加

`src/compose.rs` の `extract_service_dangerous_settings()` に検出ロジックを追加します。

### パターン

```rust
// ブーリアン設定の例（privileged: true）
if service.get("new_setting")
    .and_then(|v| v.as_bool())
    .unwrap_or(false)
{
    flags.push(DangerousFlag::NewFlag);
}

// 文字列設定の例（network_mode: host）
if let Some(mode) = service.get("new_mode").and_then(|v| v.as_str()) {
    if mode == "host" {
        flags.push(DangerousFlag::NewModeHost);
    }
}

// リスト設定の例（cap_add: [SYS_ADMIN]）
if let Some(items) = service.get("new_list").and_then(|v| v.as_sequence()) {
    for item in items {
        if let Some(s) = item.as_str() {
            flags.push(DangerousFlag::NewListItem(s.to_string()));
        }
    }
}
```

テストは `compose.rs` 内の `mod tests` に Compose YAML 文字列を使って書きます:

```rust
#[test]
fn test_parse_compose_new_setting() {
    let yaml_str = r#"
services:
  web:
    image: ubuntu
    new_setting: true
"#;
    let dir = tempfile::tempdir().unwrap();
    let compose_path = dir.path().join("compose.yml");
    std::fs::write(&compose_path, yaml_str).unwrap();

    let analysis = analyze_compose(&compose_path).unwrap();
    assert!(analysis.dangerous_flags.iter().any(|f| matches!(f, DangerousFlag::NewFlag)));
}
```
