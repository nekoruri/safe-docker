# CLAUDE.md

このファイルは AI エージェント（Claude Code 等）がこのリポジトリで作業する際のガイドです。

## プロジェクト概要

safe-docker は、コーディングエージェントに **安全に Docker 操作権限を渡す**ための Claude Code PreToolUse hook（Rust 製）です。

## 技術スタック

- **言語**: Rust (edition 2024)
- **ビルド**: Cargo
- **テスト**: cargo test（ユニット + 統合 + セキュリティ + proptest）
- **ベンチマーク**: criterion (`cargo bench`)
- **静的解析**: clippy (`cargo clippy -- -D warnings`)

## コマンド

```bash
# ビルド
cargo build --release

# 全テスト実行
cargo test

# 特定テストの実行
cargo test test_name

# 静的解析（警告をエラー扱い）
cargo clippy -- -D warnings

# ベンチマーク
cargo bench
```

## ディレクトリ構成

```
src/
├── main.rs            # エントリポイント、process_command()
├── hook.rs            # stdin/stdout の JSON プロトコル、Decision 型
├── shell.rs           # シェルコマンドのパース（パイプ/チェイン分割、間接実行検出）
├── docker_args.rs     # Docker CLI 引数のパース（サブコマンド、フラグ、マウント）
├── path_validator.rs  # パス検証（環境変数展開、正規化、$HOME 判定）
├── policy.rs          # ポリシー評価（deny/ask/allow の判定ロジック）
├── compose.rs         # docker-compose.yml の解析（volumes、危険設定）
├── config.rs          # TOML 設定ファイルの読み込み
└── error.rs           # エラー型定義

tests/
├── integration_test.rs  # バイナリレベルの E2E テスト
├── security_test.rs     # セキュリティバイパス検出テスト
└── proptest_test.rs     # ランダム入力によるクラッシュ耐性テスト

benches/
└── benchmark.rs         # criterion ベンチマーク
```

## アーキテクチャ

処理フロー:
```
stdin (JSON) → hook::read_input()
  → hook::extract_command()     # Bash ツール以外は即 allow
  → shell::split_commands()     # パイプ/チェイン/改行で分割
  → 各セグメントに対して:
      → shell::detect_shell_wrappers()  # eval/bash -c 等の間接実行検出
      → shell::is_docker_command()      # docker コマンド判定
      → shell::extract_docker_args()    # 引数抽出
      → docker_args::parse_docker_args() # 構造化パース
      → policy::evaluate()              # ポリシー評価
  → deny > ask > allow で集約
  → stdout (JSON) or 無出力 (allow)
```

## 設計原則

### Fail-safe
判断できない入力は deny または ask。入力エラー、パースエラー、巨大入力はすべて deny。

### セキュリティ修正時の注意
- 新しい危険フラグを追加する場合: `DangerousFlag` enum → `parse_docker_args()` で検出 → `policy::evaluate()` で判定
- 新しいパス検証を追加する場合: `DockerCommand::host_paths` に追加 → policy が自動で検証
- Compose の危険設定: `extract_service_dangerous_settings()` に追加
- **テストは必須**: セキュリティツールなので、すべての修正にテストを付ける
- **clippy を通す**: `cargo clippy -- -D warnings` が通ること

### is_flag_with_value() の重要性
`docker_args.rs` の `is_flag_with_value()` は、値を取るフラグのリスト。ここに不足があると、次の引数（値）がイメージ名やフラグとして誤認され、後続の危険フラグが検出されなくなる。新しいフラグを個別処理する場合でも、非 host 値のスキップ用にこのリストにも追加すること。

## テストの書き方

- **ユニットテスト**: 各 `src/*.rs` 内の `#[cfg(test)] mod tests`
- **統合テスト**: `tests/integration_test.rs` — バイナリを実際に起動して stdin/stdout で検証
- **セキュリティテスト**: `tests/security_test.rs` — バイパスパターンの検出を検証
- **DockerCommand 構造体**: テストで構築する際は `host_paths: vec![]` を忘れずに
