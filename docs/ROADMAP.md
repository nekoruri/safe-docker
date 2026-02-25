# safe-docker ロードマップ

このドキュメントはプロジェクトの長期タスクと進行状況を記録します。

## リリース履歴

| バージョン | 日付 | 主な変更 |
|-----------|------|---------|
| v0.1.0 | - | 初期リリース。Hook モード（Claude Code PreToolUse） |
| v0.2.0 | - | セキュリティ強化（security-opt, namespace flags, docker cp/build パス検証, Compose 危険設定検出） |
| v0.3.0 | 2026-02 | Wrapper モード追加（docker 置換、対話的確認、--dry-run、--verbose、監査ログ mode フィールド） |
| v0.4.0 | 予定 | セキュリティ強化（コンテナ間 namespace 共有検出、mount propagation 検出、sensitive_paths 拡充）、Artifact Attestations 導入 |

## 完了済みタスク

### Phase 1: Hook モード (v0.1.0)
- [x] stdin/stdout JSON プロトコル
- [x] シェルコマンド分割（パイプ、チェイン、改行）
- [x] Docker CLI 引数パース
- [x] パス検証（$HOME 判定、パストラバーサル防止）
- [x] ポリシー評価エンジン（deny/ask/allow）
- [x] 設定ファイル（TOML）

### Phase 2: セキュリティ強化 (v0.2.0)
- [x] --security-opt 危険値検出（apparmor, seccomp, systempaths, no-new-privileges）
- [x] 名前空間フラグ検出（--userns, --cgroupns, --ipc）
- [x] docker cp / docker build のホストパス検証
- [x] docker-compose.yml 危険設定検出（privileged, network_mode, pid, cap_add, security_opt, devices）
- [x] docker exec --privileged 検出
- [x] docker buildx build 対応
- [x] 監査ログ（JSONL / OTLP）
- [x] proptest によるファジング

### Phase 3: Wrapper モード (v0.3.0)
- [x] ラッパーモード基本動作（argv[0] 判定、docker exec、プロセス置換）
- [x] 本物の docker バイナリ検索（設定 > 環境変数 > PATH 自動検索）
- [x] 再帰呼び出し防止（SAFE_DOCKER_ACTIVE）
- [x] --dry-run, --verbose, --help, --version, --docker-path オプション
- [x] Ask の対話的確認（TTY 判定、非対話環境設定）
- [x] 監査ログに mode フィールド追加
- [x] コンテキスト固有の Tip メッセージ（generate_tips）
- [x] エッジケーステスト充実

### Phase 4: 配布とセキュリティ強化 (v0.4.0)
- [x] GitHub Artifact Attestations（Sigstore ベース署名）
- [x] SHA256 チェックサムファイル同梱
- [x] docs/SUPPLY_CHAIN_SECURITY.md（エコシステム解説）
- [x] README インストールセクション刷新（検証手順、cargo install）
- [x] コンテナ間 namespace 共有検出（--network/--pid/--ipc=container:NAME）
- [x] mount propagation 検出（shared/rshared → deny）
- [x] sensitive_paths デフォルト拡充（.terraform, .vault-token, .config/gh, .npmrc, .pypirc）
- [x] Compose の container:/service: namespace 参照検出

## 未着手タスク

### セキュリティ: 攻撃面の網羅的レビュー
- [ ] 学術論文・CVE データベースとの突合によるギャップ分析
- [ ] Docker API 直接呼び出し（REST API / SDK）の検出限界の文書化
- [ ] BuildKit --secret / --ssh フラグの検証
- [ ] --add-host / --dns によるネットワーク設定操作の検出
- [ ] Compose `include:` ディレクティブ（外部ファイル参照）の対応
- [ ] tmpfs サイズ制限なしの検出

### 機能: ask レベル化
- [ ] ask に deep/minor のレベルを導入
- [ ] 非対話環境で minor ask のみ自動許可するオプション
- [ ] CI/CD 環境で安全に SAFE_DOCKER_ASK=allow を使えるようにする

### 機能: インストール体験の向上
- [ ] Homebrew tap の作成
- [ ] crates.io への公開（`cargo install safe-docker`）
- [ ] シンボリックリンク setup ヘルパーコマンド

### テスト
- [ ] 多環境 smoke テスト（Linux glibc/musl, macOS Intel/Apple Silicon）
- [ ] 複数 Docker デーモン環境テスト（colima, orbstack）
- [ ] 大規模 compose ファイル（1000行超）のパフォーマンステスト

### ドキュメント
- [ ] is_flag_with_value() リスト更新ガイド
- [ ] 新しい危険フラグ追加時のチェックリスト
- [ ] OPA Docker AuthZ との統合ガイド

## 設計メモ

### セキュリティモデルの制限（既知・受容済み）

以下はセキュリティツールとしての根本的な制限であり、OPA Docker AuthZ 等の別レイヤーで補完する:

1. **スクリプトファイル経由のバイパス**: Write ツールでシェルスクリプトを作成し `bash script.sh` で実行された場合、script 内の docker コマンドは検査できない
2. **Docker API 直接呼び出し**: curl や SDK でソケット/TCP 経由の API を直接叩かれると検出不能
3. **複雑なシェル構文**: 関数定義内、case 文内、変数展開経由の docker コマンドは検出困難
4. **Wrapper モードの迂回**: `/usr/bin/docker` を直接呼べば safe-docker をスキップできる（設計上の特性、「うっかりミス防止」が目的）
