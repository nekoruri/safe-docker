# safe-docker ロードマップ

このドキュメントはプロジェクトの長期タスクと進行状況を記録します。

## リリース履歴

| バージョン | 日付 | 主な変更 |
|-----------|------|---------|
| v0.1.0 | - | 初期リリース。Hook モード（Claude Code PreToolUse） |
| v0.2.0 | - | セキュリティ強化（security-opt, namespace flags, docker cp/build パス検証, Compose 危険設定検出） |
| v0.3.0 | 2026-02 | Wrapper モード追加（docker 置換、対話的確認、--dry-run、--verbose、監査ログ mode フィールド） |
| v0.4.0 | 2026-02 | セキュリティ強化（コンテナ間 namespace 共有検出、mount propagation 検出、sensitive_paths 拡充）、Artifact Attestations 導入 |
| v0.5.0 | 2026-02 | セキュリティ大幅強化: パーサー正確性改善、ホストファイル読み取り防止、capability 拡充、sysctl/add-host 検出、ビルド時安全性、Compose env_file/include/sysctls 対応 |
| v0.6.0 | 2026-02 | 実運用品質向上: 診断機能強化、監査ログ config_source、macOS 対応修正、多環境 CI（macOS/musl）、MSRV 設定、CONTRIBUTING.md |

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

### Phase 5: セキュリティ大幅強化 (v0.5.0)

#### 5a: パーサー正確性の改善
- [x] `is_flag_with_value()` 欠損フラグ補完（`--env-file`, `--label-file`, `--uts`, `--pid`, `--device-*`, `--cpu-*` 等 25+ フラグ）
- [x] `--uts=host` 検出（CIS 5.11 準拠。`DangerousFlag::UtsHost` 追加）
- [x] `--uts` の Compose 対応（`uts: host`）

#### 5b: ホストファイル読み取りの防止
- [x] `--env-file PATH` のパス検証（$HOME 外 → deny、sensitive_paths → ask）
- [x] `--label-file PATH` のパス検証
- [x] `--security-opt seccomp=PROFILE_PATH` のパス検証（`unconfined` 以外のパスを検証）
- [x] Compose `env_file:` の対応（文字列・リスト・マッピング形式の全パース、$HOME 外 → deny）

#### 5c: blocked_capabilities デフォルト拡充
- [x] `DAC_READ_SEARCH` 追加（`open_by_handle_at(2)` によるファイルシステム直接アクセス）
- [x] `NET_ADMIN` 追加（iptables 操作、ARP スプーフィング、promiscuous モード）
- [x] `BPF` 追加（eBPF プログラムロード。カーネル空間でコード実行）
- [x] `PERFMON` 追加（パフォーマンスモニタリング。サイドチャネル攻撃）
- [x] `SYS_BOOT` 追加（ホスト再起動）

#### 5d: ネットワーク/カーネル操作の検出
- [x] `--sysctl` 危険値検出（`kernel.*` → deny、`net.*` → ask、その他 → allow）
- [x] `--add-host` のメタデータ IP 検出（169.254.169.254、fd00:ec2::254 → ask）
- [x] Compose `sysctls:` の対応（リスト形式・マッピング形式の両方）
- [x] CIS 5.2 対応: `--security-opt label=disable` / `label:disable` 検出

#### 5e: ビルド時の安全性
- [x] `docker build --build-arg` の機密情報パターン検出（`SECRET`, `PASSWORD`, `TOKEN`, `KEY` → ask）
- [x] BuildKit `--secret` / `--ssh` フラグの検証（ソースパスの $HOME 外アクセス → deny）
- [x] Compose `include:` ディレクティブ（外部ファイル参照）の対応（$HOME 外 → ask）

## 未着手タスク

> 攻撃面分析の詳細は [docs/ATTACK_SURFACE_ANALYSIS.md](ATTACK_SURFACE_ANALYSIS.md) を参照。

### 機能: ask レベル化
- [ ] ask に deep/minor のレベルを導入
- [ ] 非対話環境で minor ask のみ自動許可するオプション
- [ ] CI/CD 環境で安全に SAFE_DOCKER_ASK=allow を使えるようにする

### 機能: インストール体験の向上
- [ ] Homebrew tap の作成
- [ ] crates.io への公開（`cargo install safe-docker`）
- [ ] シンボリックリンク setup ヘルパーコマンド

### テスト・CI
- [x] 多環境 smoke テスト（Linux glibc/musl, macOS Apple Silicon）
- [ ] 複数 Docker デーモン環境テスト（colima, orbstack）
- [x] 大規模 compose ファイル（1000行超）のパフォーマンステスト
- [x] MSRV (Minimum Supported Rust Version) CI チェック（Rust 1.88）
- [x] CI キャッシュ最適化（PR ビルドでのキャッシュ保存抑制）

### ドキュメント
- [x] is_flag_with_value() リスト更新ガイド
- [x] 新しい危険フラグ追加時のチェックリスト
- [x] OPA Docker AuthZ との統合ガイド

## 設計メモ

### セキュリティモデルの制限（既知・受容済み）

以下はセキュリティツールとしての根本的な制限であり、OPA Docker AuthZ 等の別レイヤーで補完する:

1. **スクリプトファイル経由のバイパス**: Write ツールでシェルスクリプトを作成し `bash script.sh` で実行された場合、script 内の docker コマンドは検査できない
2. **Docker API 直接呼び出し**: curl や SDK でソケット/TCP 経由の API を直接叩かれると検出不能
3. **複雑なシェル構文**: 関数定義内、case 文内、変数展開経由の docker コマンドは検出困難
4. **Wrapper モードの迂回**: `/usr/bin/docker` を直接呼べば safe-docker をスキップできる（設計上の特性、「うっかりミス防止」が目的）
