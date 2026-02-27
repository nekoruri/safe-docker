# CLAUDE.md

このファイルは AI エージェント（Claude Code 等）がこのリポジトリで作業する際のガイドです。

## プロジェクト概要

safe-docker は、コーディングエージェントや開発者に **安全に Docker 操作権限を渡す**ためのセキュリティツール（Rust 製）。2つの動作モードを持つ:

- **Hook モード**: Claude Code PreToolUse hook として stdin/stdout の JSON プロトコルで動作
- **Wrapper モード**: `docker` コマンドの直接置換として CLI 引数で動作

## 技術スタック

- **言語**: Rust (edition 2024)
- **ビルド**: Cargo
- **テスト**: cargo test（ユニット + 統合 + セキュリティ + proptest）
- **ベンチマーク**: criterion (`cargo bench`)
- **静的解析**: clippy (`cargo clippy -- -D warnings`)

## 開発環境の初期設定

作業開始時に以下を実行して pre-commit hook を有効化すること:

```bash
git config core.hooksPath scripts
```

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
├── main.rs            # エントリポイント、モード判別（Hook/Wrapper）、--check-config
├── wrapper.rs         # ラッパーモード（evaluate_docker_args, exec_docker, find_real_docker, handle_ask）
├── setup.rs           # setup サブコマンド（シンボリックリンク作成、PATH 確認）
├── hook.rs            # Hook モード: stdin/stdout の JSON プロトコル、Decision 型
├── shell.rs           # シェルコマンドのパース（パイプ/チェイン分割、間接実行検出）※Hook モードのみ
├── docker_args.rs     # Docker CLI 引数のパース（サブコマンド、フラグ、マウント）※両モード共通
├── path_validator.rs  # パス検証（環境変数展開、正規化、$HOME 判定）※両モード共通
├── policy.rs          # ポリシー評価（deny/ask/allow の判定ロジック）※両モード共通
├── compose.rs         # docker-compose.yml の解析（volumes、危険設定）※両モード共通
├── config.rs          # TOML 設定ファイルの読み込み（[wrapper] セクション含む）
├── audit.rs           # 監査ログ（JSONL / OTLP）※両モード共通、mode フィールドで区別
├── error.rs           # エラー型定義
└── test_utils.rs      # テスト用ユーティリティ（TempEnvVar, EnvLock, env_lock）※#[cfg(test)]

tests/
├── integration_test.rs    # Hook モードの E2E テスト（stdin/stdout）
├── wrapper_test.rs        # Wrapper モードの E2E テスト（/bin/echo をモック docker として使用）
├── security_test.rs       # セキュリティバイパス検出テスト
├── proptest_test.rs       # ランダム入力によるクラッシュ耐性テスト
└── opa_consistency_test.rs  # OPA authz.rego と safe-docker デフォルトの一貫性検証

benches/
└── benchmark.rs         # criterion ベンチマーク
```

## アーキテクチャ

### モード判別（main.rs）
```
argv[0] が "docker"/"docker-compose"  → Wrapper モード（透過）
CLI 引数あり                           → Wrapper モード（明示的）
CLI 引数なし                           → Hook モード（stdin JSON）
```

### Hook モードの処理フロー
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

### Wrapper モードの処理フロー
```
OS 引数 → wrapper::run()
  → 再帰呼び出し防止チェック (SAFE_DOCKER_ACTIVE)
  → バイパスチェック (SAFE_DOCKER_BYPASS)
  → docker_args::parse_docker_args()  # shell.rs をスキップし直接パース
  → policy::evaluate()                # ポリシー評価
  → Decision に応じたアクション:
      Allow → exec_docker() (プロセス置換、戻らない)
      Deny  → stderr にエラー + exit 1
      Ask   → handle_ask() (TTY なら y/N プロンプト、非 TTY なら設定に従う)
```

## 設計原則

### Fail-safe
判断できない入力は deny または ask。入力エラー、パースエラー、巨大入力はすべて deny。

### セキュリティ修正時の注意
- 新しい危険フラグを追加する場合: `DangerousFlag` enum → `parse_docker_args()` で検出 → `policy::evaluate()` で判定
- 新しいパス検証を追加する場合: `DockerCommand::host_paths` に追加 → policy が自動で検証
- Compose の危険設定: `extract_service_dangerous_settings()` に追加
- Compose のホストファイル参照: `extract_service_env_file_paths()` で `env_file_paths` に追加 → policy が deny で検証
- Compose の外部ファイル参照: `extract_include_paths()` で `host_paths` に追加 → policy が ask で検証
- **テストは必須**: セキュリティツールなので、すべての修正にテストを付ける
- **clippy を通す**: `cargo clippy -- -D warnings` が通ること

### is_flag_with_value() の重要性
`docker_args.rs` の `is_flag_with_value()` は、値を取るフラグのリスト。ここに不足があると、次の引数（値）がイメージ名やフラグとして誤認され、後続の危険フラグが検出されなくなる。新しいフラグを個別処理する場合でも、非 host 値のスキップ用にこのリストにも追加すること。

## テストの書き方

- **ユニットテスト**: 各 `src/*.rs` 内の `#[cfg(test)] mod tests`
- **統合テスト**: `tests/integration_test.rs` — バイナリを実際に起動して stdin/stdout で検証
- **セキュリティテスト**: `tests/security_test.rs` — バイパスパターンの検出を検証
- **DockerCommand 構造体**: テストで構築する際は `host_paths: vec![]` を忘れずに
- **環境変数を操作するテスト**: `test_utils::TempEnvVar` と `env_lock()` を使うこと。`unsafe { std::env::set_var() }` を直接呼ばない
  ```rust
  use crate::test_utils::{TempEnvVar, env_lock};
  let lock = env_lock();
  let _env = TempEnvVar::set(&lock, "MY_VAR", "value");  // Drop 時に自動復元
  ```
