# 監査ログ + OTLP JSON 対応 設計書

## Context

safe-docker は、判定結果を stdout の JSON (Claude Code hook プロトコル) と stderr のログ (`env_logger`) に出力する。事後分析・可視化・セキュリティ監査のために、構造化された監査ログを永続ファイルに出力する機能を追加した。出力形式は JSONL (軽量独自スキーマ) と OTLP JSON Lines (OTel Collector 互換) の2種。

## 方針

- **JSONL**: 常に利用可能。追加依存なし
- **OTLP JSON**: Cargo feature `otlp` で有効化。手動定義の OTLP 構造体を使用（外部依存なし）
- **OTel データモデル**: LogRecord を使用 (Span ではない。各 hook 呼び出しは duration のない単一評価イベント)
- **性能**: hook レスポンス (stdout JSON) の後にファイル I/O。audit 無効時はゼロオーバーヘッド

## プラットフォーム互換性

| プラットフォーム | OTLP Logs | 必要な Resource 属性 | 備考 |
|----------------|-----------|---------------------|------|
| **Datadog** | 対応 | `service.name` (必須), `deployment.environment.name`, `host.name` | Severity 自動マッピング、属性は DD タグに変換 |
| **New Relic** | 対応 | `service.name` (必須), `service.version` | Severity 自動マッピング |
| **Grafana/Loki** | 対応 (Collector 経由) | `service.name` | OTel Collector → Loki exporter |
| **LangFuse** | **非対応 (Traces のみ)** | — | GenAI Span 専用。LogRecord は取り込めない |

**LangFuse 対応について**: LangFuse は OTLP Traces (Span) のみをサポートし、LogRecord は受け付けない。safe-docker の監査イベントは duration を持たない単一評価であり、本質的に LogRecord が適切なため、LangFuse 互換のために Span を生成するのは OTel のセマンティクスに反する。将来的に LangFuse が Logs 対応すれば自動的に互換になる。

## アーキテクチャ

### 処理フロー

```
stdin (JSON) → hook::read_input()
  → hook::extract_command()
  → Config::load()
  → audit::is_enabled() で判定
  → AuditCollector 生成 (enabled 時のみ)
  → process_command_with_audit() で各セグメントを処理
      → collector.record_docker_command() でメタデータ蓄積
  → hook::output_decision()  ★ここで stdout に hook レスポンス
  → audit::build_event() → audit::emit()  ★レスポンス後にファイル I/O
```

### 変更ファイル

| ファイル | 変更内容 |
|---------|---------|
| `Cargo.toml` | `otlp` feature + `opentelemetry-proto` optional 依存 + `gethostname` 依存追加 |
| `src/main.rs` | `pub mod audit` 追加、`process_command_with_audit()` 新設、`main()` に audit 統合 |
| `src/audit.rs` | **新規作成** — AuditEvent, AuditCollector, JSONL/OTLP 出力 |
| `src/config.rs` | `AuditConfig`, `AuditFormat` 追加、`Config` に `audit` フィールド追加 |
| `src/docker_args.rs` | `DockerSubcommand` に `Display` トレイト実装 |

## AuditEvent スキーマ (JSONL)

```json
{
  "timestamp_unix_nano": 1234567890000000000,
  "session_id": "claude-session-id",
  "command": "docker run -v /etc:/data ubuntu",
  "decision": "deny",
  "reason": "[safe-docker] Path /etc is outside $HOME",
  "docker_subcommand": "run",
  "docker_image": "ubuntu",
  "bind_mounts": ["/etc"],
  "dangerous_flags": [],
  "cwd": "/home/user/project",
  "pid": 12345,
  "host_name": "my-host",
  "environment": "development"
}
```

## OTel LogRecord マッピング

### Resource 属性

| Resource 属性 | 値 | 重要度 |
|--------------|---|--------|
| `service.name` | `"safe-docker"` | 必須 (全プラットフォーム) |
| `service.version` | `env!("CARGO_PKG_VERSION")` | 推奨 |
| `deployment.environment.name` | env `SAFE_DOCKER_ENV` or `"development"` | DD 推奨 |
| `host.name` | `gethostname()` | DD/NR 推奨 |

### LogRecord フィールド

| フィールド | 値 |
|-----------|---|
| severity_number | allow=9(INFO), ask=13(WARN), deny=17(ERROR) |
| severity_text | "INFO" / "WARN" / "ERROR" |
| body | reason 文字列 (allow の場合 None) |

### LogRecord 属性

| 属性 | 値 | 用途 |
|------|---|------|
| `decision` | "allow" / "deny" / "ask" | フィルタリング・ダッシュボード |
| `command` | 元コマンド文字列 | 調査・デバッグ |
| `session_id` | Claude Code セッション ID | セッション相関 |
| `cwd` | 作業ディレクトリ | コンテキスト |
| `docker.subcommand` | "run" 等 | フィルタリング |
| `docker.image` | イメージ名 | フィルタリング |
| `docker.bind_mounts` | パス配列 | セキュリティ分析 |
| `docker.dangerous_flags` | フラグ配列 | セキュリティ分析 |
| `process.pid` | プロセス ID | デバッグ |

## エラーハンドリング

- 監査ログの失敗は **Decision に絶対に影響しない**
- write エラーは `log::warn!` のみ
- パニック不可 — `unwrap()` 禁止、`unwrap_or_default()` / `if let` を使用
- ディレクトリ不存在時は `create_dir_all()` で自動作成

## 設定

### config.toml

```toml
[audit]
enabled = true
format = "both"          # "jsonl" | "otlp" | "both"
jsonl_path = "~/.local/share/safe-docker/audit.jsonl"
otlp_path = "~/.local/share/safe-docker/audit-otlp.jsonl"
```

### 環境変数

- `SAFE_DOCKER_AUDIT=1`: 設定ファイルなしでも監査ログを有効化
- `SAFE_DOCKER_ENV`: deployment environment 名 (デフォルト: `"development"`)

## ビルド・テスト

```bash
# 通常ビルド (JSONL のみ)
cargo build --release

# OTLP 付きビルド
cargo build --release --features otlp

# テスト
cargo test
cargo test --features otlp

# Clippy
cargo clippy -- -D warnings
cargo clippy --features otlp -- -D warnings
```

## 手動テスト

```bash
# JSONL 出力確認
SAFE_DOCKER_AUDIT=1 sh -c 'echo "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"docker run -v /etc:/data ubuntu\"}}" | cargo run'
cat ~/.local/share/safe-docker/audit.jsonl
```
