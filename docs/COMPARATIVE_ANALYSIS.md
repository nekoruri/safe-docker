# Docker 操作制御の類似プロジェクト・研究の比較分析

コーディングエージェントの Docker 操作を安全に制御するという safe-docker の試みを、既存のプロジェクト・学術研究・業界動向と比較し、改善の方向性を導出する。

## 調査の範囲

調査は以下の5つの観点から実施した:

1. **Docker 認可プラグイン** — Docker デーモンレベルのアクセス制御
2. **Kubernetes ポリシーエンジン** — コンテナオーケストレーションにおけるポリシー強制の最先端
3. **AI エージェント向けサンドボックス** — LLM/コーディングエージェント固有の隔離アプローチ
4. **ランタイムセキュリティ** — カーネルレベルの検出・強制ツール
5. **学術研究** — コンテナセキュリティポリシーの理論的基盤

---

## 1. Docker 認可プラグイン

Docker デーモンのデフォルトの認可モデルは「全か無か（all-or-nothing）」であり、Docker ソケットにアクセスできるユーザーは任意の Docker コマンドを実行できる。認可プラグインはこのギャップを埋める。

### 1.1 OPA Docker AuthZ

| 項目 | 詳細 |
|------|------|
| **URL** | https://github.com/open-policy-agent/opa-docker-authz |
| **言語** | Go |
| **動作レイヤー** | Docker デーモン（Authorization Plugin API） |
| **ポリシー言語** | Rego（OPA ネイティブ） |
| **メンテナンス** | 活発（v0.10、2025年4月リリース） |

**仕組み**: Docker デーモンが全ての API リクエストをプラグインにルーティングし、OPA がRegoポリシーで評価する。マネージドプラグイン（v2）として Docker が自動でライフサイクル管理する。

**主な特徴**:
- バインドマウントのシンボリックリンク解決（`listBindMounts()`でバイパス防止）
- 決定ログの JSON 出力
- リモートバンドルによるポリシー配信
- TLS 必須でクライアントユーザーを認証

**制約**: Docker デーモンの設定変更と TLS 設定が必要。ポリシー未設定時は全リクエストを許可（fail-open）。

### 1.2 Casbin Docker AuthZ

| 項目 | 詳細 |
|------|------|
| **URL** | https://github.com/casbin/casbin-authz-plugin |
| **言語** | Go |
| **動作レイヤー** | Docker デーモン（Authorization Plugin API） |
| **ポリシーモデル** | RBAC / ABAC |

**仕組み**: Docker API の HTTP メソッドとURL パスの組み合わせで RBAC/ABAC アクセス制御を実現する。Casbin のポリシーモデル（model.conf + policy.csv）でルールを定義。

**safe-docker との違い**: Casbin はユーザーの「ロール」に基づく制御。safe-docker はコマンドの「内容」に基づく制御。エージェントの場合、ユーザーは常に1人なので RBAC の価値は薄く、コマンド内容の精査が重要。

### 1.3 Docker Enhanced Container Isolation (ECI)

| 項目 | 詳細 |
|------|------|
| **URL** | https://docs.docker.com/enterprise/security/hardened-desktop/enhanced-container-isolation/ |
| **提供元** | Docker Inc. |
| **動作レイヤー** | コンテナランタイム（Sysbox） |
| **対象** | Docker Desktop Business |

**仕組み**: ECI を有効にすると、コンテナは自動的に Sysbox ランタイム（runc のセキュリティ強化フォーク）で実行される。Linux user namespace による隔離、VM の不変性保証、/proc・/sys の仮想化、`--privileged` フラグの安全な処理を行う。

**制約**: Docker Business サブスクリプション必須。2025年の CVE-2025-9074 では ECI 有効時でも悪意あるコンテナがホストを侵害できる脆弱性が報告された。

---

## 2. Kubernetes ポリシーエンジン

Kubernetes エコシステムのポリシー強制は、コンテナセキュリティの最先端であり、safe-docker に応用可能な設計パターンの宝庫である。

### 2.1 Kubernetes Admission Controllers

**ValidatingAdmissionPolicy（v1.30 GA）**: Webhook サーバー不要で CEL（Common Expression Language）式をインラインで記述。API Server 内部で評価されるため高速。

```yaml
# 例: 全コンテナで runAsNonRoot を強制
validations:
- expression: "object.spec.containers.all(c, c.securityContext.runAsNonRoot == true)"
  message: "Containers must run as non-root"
```

**safe-docker への示唆**: CEL のような宣言的な式言語を設定ファイルで使えると、Rust コードを変更せずにポリシーを拡張できる。ただし、safe-docker の 1ms 以下のレイテンシ要件との兼ね合いが重要。

### 2.2 OPA Gatekeeper

| 項目 | 詳細 |
|------|------|
| **URL** | https://open-policy-agent.github.io/gatekeeper/ |
| **成熟度** | CNCF Graduated (2021年) |
| **ポリシー言語** | Rego |

**設計パターン — ConstraintTemplate + Constraint**:
ポリシーの「ロジック」と「パラメータ」を分離する二層構造。テンプレートで検証ロジックを定義し、Constraint でパラメータを渡してインスタンス化する。

```yaml
# ConstraintTemplate: ロジックの定義
spec:
  targets:
    - rego: |
        violation[{"msg": msg}] {
          not input.review.object.metadata.labels[input.parameters.label]
          msg := sprintf("Missing label: %s", [input.parameters.label])
        }

# Constraint: パラメータの指定
spec:
  parameters:
    label: "team"
```

**Audit Controller**: 既存リソースの違反を定期的にスキャンし、事後的にポリシー違反を検出する。

### 2.3 Kyverno

| 項目 | 詳細 |
|------|------|
| **URL** | https://kyverno.io/ |
| **成熟度** | CNCF Graduated (2024年7月) |
| **ポリシー言語** | YAML + CEL (v1.11+) |

**特徴**: ポリシーを Kubernetes マニフェストと同じ YAML で記述でき、Rego のような専用言語の学習コストが不要。

**3種類の操作**:
- **Validate（検証）**: リソースを検証して拒否
- **Mutate（変更）**: リソースのフィールドを自動変更（デフォルト値注入など）
- **Generate（生成）**: 連動リソースの自動生成

**validationFailureAction**: `Enforce`（拒否）と `Audit`（ログのみ）を宣言的に切り替え可能。

**イメージ署名検証**: Sigstore/Cosign と統合し、コンテナイメージの出自を暗号的に検証。

### 2.4 Pod Security Standards / Pod Security Admission (PSA)

| 項目 | 詳細 |
|------|------|
| **動作レイヤー** | API Server 組み込み |
| **成熟度** | Kubernetes v1.25 GA |

**3段階のセキュリティレベル**:

| レベル | 説明 |
|--------|------|
| **Privileged** | 制限なし |
| **Baseline** | 既知の権限昇格を防止（hostNetwork, hostPID, 特権コンテナ等をブロック） |
| **Restricted** | 最も厳格（runAsNonRoot必須, capabilities drop ALL, seccomp必須等） |

**3つの動作モード**: enforce（拒否）、audit（ログ）、warn（警告）を同一ルールに同時指定可能。

**safe-docker への示唆**: 事前定義のセキュリティプロファイルとバージョニングの概念は、safe-docker の設定にそのまま応用可能。

---

## 3. AI エージェント向けサンドボックス

コーディングエージェントの Docker/コード実行セキュリティは、2024-2025年に急速に発展した領域である。

### 3.1 E2B (Execute to Build)

| 項目 | 詳細 |
|------|------|
| **URL** | https://e2b.dev/ |
| **隔離技術** | Firecracker microVM |
| **起動時間** | <200ms |
| **ライセンス** | Apache-2.0 |

**仕組み**: Firecracker microVM で各サンドボックスを完全に隔離する。各 microVM が独自のカーネルを持ち、ホストカーネルを共有するコンテナと根本的に異なるセキュリティモデルを提供する。

**セキュリティアーキテクチャ**:
- ハードウェアレベル隔離（KVM ベース）
- Firecracker の「jailer」プロセスによる VMM 自体の隔離（cgroups + namespaces）
- <5 MiB のメモリオーバーヘッドで高密度デプロイ可能
- スナップショットによる高速復元

**safe-docker との根本的な違い**: E2B は「隔離」アプローチ（何をしてもホストに影響しない環境を提供）。safe-docker は「フィルタリング」アプローチ（危険な操作を識別してブロック）。隔離はより強固だが、ホスト環境へのアクセスが必要なユースケース（ローカルファイルの編集、ホストサービスとの連携）には不向き。

### 3.2 OpenHands (旧 OpenDevin)

| 項目 | 詳細 |
|------|------|
| **URL** | https://github.com/OpenHands/OpenHands |
| **論文** | [OpenHands: An Open Platform for AI Software Developers (arXiv:2407.16741)](https://arxiv.org/abs/2407.16741) |
| **GitHub Stars** | 64k+ (2025年時点) |

**サンドボックスアーキテクチャ**:
- 各セッションが Docker コンテナ内で実行され、ホストから隔離
- V1 SDK でモジュラー化: opt-in サンドボックス、再利用可能な agent/tool/workspace パッケージ
- WebSocket による双方向通信（エージェント ↔ リモートランタイム）
- ローカル開発とリモートの安全なコンテナ環境をシームレスに切り替え可能

### 3.3 Claude Code PreToolUse Hooks エコシステム

Claude Code の hook システムを活用したセキュリティツールは safe-docker 以外にも存在する。

**claude-code-permissions-hook** ([kornysietsma](https://github.com/kornysietsma/claude-code-permissions-hook)):

| 項目 | 詳細 |
|------|------|
| **言語** | Rust |
| **対象** | 全ツール（Bash, Read, Write, Task 等） |
| **設定** | TOML（regex ベースのルール） |

**仕組み**: Deny → Allow → Passthrough の順でルール評価。正規表現でコマンドパターンをマッチし、exclude 正規表現で例外を処理する。

```toml
[[allow]]
tool = "Bash"
command_regex = "^cargo (build|test|check|clippy|fmt|run)"
command_exclude_regex = "&|;|\\||\`|\\$\\("

[[deny]]
tool = "Read"
file_path_regex = "\\.(env|secret)$"
```

**safe-docker との比較**:
- **スコープ**: permissions-hook は全ツールの汎用フィルタ。safe-docker は Docker 操作に特化
- **ポリシー表現**: regex ベース vs Rust で実装された構造化パーサー
- **Docker 理解度**: permissions-hook は Docker の構文を理解しない（正規表現マッチのみ）。safe-docker は Docker CLI の引数を構造化パースし、マウントパスの正規化、docker-compose.yml の解析、間接実行の検出などを行う
- **セキュリティ深度**: Docker に対しては safe-docker の方が圧倒的に堅牢（構造化パースにより、引用符やエスケープによるバイパスに強い）

### 3.4 その他のサンドボックスプラットフォーム

| プラットフォーム | 隔離技術 | 起動時間 | 主な用途 |
|-----------------|----------|----------|----------|
| **Daytona** | Container | <200ms | AI コード実行 |
| **Modal** | Container/gVisor | ~1s | サーバーレス AI |
| **microsandbox** | libkrun (MicroVM) | ~100ms | 自己ホスト型サンドボックス |
| **Fly.io** | Firecracker | ~300ms | アプリケーションホスティング |
| **Together Code Sandbox** | MicroVM | N/A | AI コーディングツール |

### 3.5 コンテナランタイムの隔離レベル比較

| ランタイム | 隔離方式 | セキュリティ | パフォーマンス | 適合性 |
|-----------|----------|------------|--------------|--------|
| **runc** (標準) | Linux namespaces + cgroups | 中（カーネル共有） | 最高 | 標準 |
| **gVisor (runsc)** | ユーザー空間カーネル（syscall インターセプト） | 高 | 中（syscall オーバーヘッド） | I/O 軽量ワークロード向け |
| **Kata Containers** | 軽量 VM（独立カーネル） | 非常に高 | 中 | ネスト仮想化必要 |
| **Firecracker** | MicroVM（KVM） | 非常に高 | 高（<125ms起動） | サーバーレス/FaaS |
| **Docker Rootless** | User namespace | 中〜高 | ほぼ同等 | 追加設定不要 |

---

## 4. ランタイムセキュリティ

コンテナ実行中の挙動を監視・強制するツールは、safe-docker の「起動前フィルタリング」と補完関係にある。

### 4.1 Falco

| 項目 | 詳細 |
|------|------|
| **URL** | https://falco.org/ |
| **成熟度** | CNCF Graduated (2024年2月) |
| **動作レイヤー** | カーネル（eBPF / kernel module） |

**仕組み**: eBPF プローブでカーネルのシステムコールを監視し、YAML ベースのルールで異常を検出・アラートする。

```yaml
- rule: Sensitive Mount in Container
  condition: >
    container and mount and
    (fd.name startswith /etc or
     fd.name startswith /var/run/docker.sock)
  output: "Sensitive path mounted (path=%fd.name container=%container.name)"
  priority: CRITICAL
```

**設計パターン**:
- **マクロ/リスト**: ルールの再利用可能な部品（DRY 原則）
- **例外（exceptions）**: ルールにホワイトリスト例外を宣言的に追加
- **8段階の優先度**: EMERGENCY 〜 DEBUG
- **タグベースのグループ制御**: ルールにタグを付けて有効/無効を一括制御

### 4.2 KubeArmor

| 項目 | 詳細 |
|------|------|
| **URL** | https://github.com/kubearmor/KubeArmor |
| **成熟度** | CNCF Sandbox |
| **動作レイヤー** | カーネル（LSM: AppArmor / BPF-LSM / SELinux） |

**仕組み**: ポリシーを LSM ルールに変換してカーネルレベルで強制。検出だけでなく**防止**も行う。

**ポリシーの粒度**:
- ファイルパス/ディレクトリ単位のアクセス制御
- プロセス実行の制御
- ネットワークプロトコル単位の制御
- Default Posture（Allow/Block/Audit）の設定

### 4.3 Tetragon (Cilium)

| 項目 | 詳細 |
|------|------|
| **URL** | https://github.com/cilium/tetragon |
| **動作レイヤー** | カーネル（eBPF） |

**仕組み**: eBPF で kprobes/tracepoints にアタッチし、プロセス・ファイル・ネットワークのイベントを収集。ポリシーベースの強制（Sigkill 等）も可能。

### 4.4 Seccomp-BPF

Docker のデフォルト seccomp プロファイルは約300+のシステムコールのうち約44個をブロック。カスタムプロファイルでさらに制限可能。`--security-opt seccomp=unconfined` の無効化を safe-docker がブロックしていることは、この防御レイヤーを保護する意味で重要。

---

## 5. 学術研究

### 5.1 コンテナセキュリティのサーベイ

**A Container Security Survey: Exploits, Attacks, and Defenses** (ACM Computing Surveys, 2024)
- 200以上のコンテナ関連脆弱性を分析し、47の exploit タイプを11の攻撃ベクトルに分類
- 参照: https://dl.acm.org/doi/10.1145/3715001

**Container Security: Precaution levels, mitigation strategies, and research perspectives** (Computers and Security, 2023)
- DREAD 脅威モデリングフレームワークを使用したコンテナインフラの体系的な脅威モデリング
- 参照: https://www.sciencedirect.com/science/article/abs/pii/S0167404823004005

### 5.2 先進的なアプローチ

**ProSPEC: Proactive Security Policy Enforcement for Containers** (ACM CODASPY 2022)
- 学習ベースの予測モデルでコンテナイベントを事前予測し、計算コストの高いセキュリティ検証をオフラインで実施
- ランタイムの強制ステップはリスト検索程度に軽量化
- ベイジアンネットワークによる遷移確率モデル
- 参照: https://dl.acm.org/doi/abs/10.1145/3508398.3511515

**safe-docker への示唆**: ProSPEC の「事前計算」の考え方は、safe-docker の docker-compose.yml 解析（コマンド実行前にファイルを読んでポリシーを評価する）と方向性が近い。

### 5.3 LLM エージェントのガードレール

**AGrail: A Lifelong Agent Guardrail** (ACL 2025)
- 反復的最適化により適応的な安全ポリシーを生成するエージェントガードレール
- 参照: https://aclanthology.org/2025.acl-long.399.pdf

**Pre-execution guardrail systems** (arXiv, 2025)
- 計画段階でエージェントの行動を予防的に分析し、有害な操作の実行前に介入する外部モニター
- 参照: https://arxiv.org/html/2510.09781v1

**safe-docker への位置づけ**: safe-docker はまさに pre-execution guardrail の一実装であり、Docker 操作に特化した「計画段階の介入」を行っている。

---

## 6. 横断比較

### 6.1 動作レイヤーと特性の比較

| ツール/アプローチ | レイヤー | 防止/検出 | バイパス耐性 | デプロイ難度 | 対象 |
|:---:|:---:|:---:|:---:|:---:|:---:|
| **safe-docker** | CLI hook | 防止 | 低 | 非常に低 | Docker CLI |
| **permissions-hook** | CLI hook | 防止 | 低 | 非常に低 | 全ツール |
| **OPA Docker AuthZ** | デーモンプラグイン | 防止 | 高 | 中 | Docker API |
| **Casbin Docker AuthZ** | デーモンプラグイン | 防止 | 高 | 中 | Docker API |
| **Docker ECI** | ランタイム | 防止 | 高 | 低 | Docker Desktop |
| **OPA Gatekeeper** | K8s API Server | 防止+監査 | 高 | 中 | K8s リソース |
| **Kyverno** | K8s API Server | 防止+変更+生成 | 高 | 中 | K8s リソース |
| **PSA** | K8s API Server 組込 | 防止+監査+警告 | 高 | 非常に低 | K8s Pod |
| **Falco** | カーネル (eBPF) | 検出 | 非常に高 | 中 | syscall |
| **KubeArmor** | カーネル (LSM) | 防止 | 非常に高 | 中 | ファイル/プロセス/ネット |
| **E2B** | MicroVM | 隔離 | 非常に高 | 低(SaaS) | コード実行全体 |
| **gVisor** | ユーザー空間カーネル | 隔離 | 高 | 中 | コンテナ全体 |

### 6.2 ポリシー定義方式の比較

| ツール | ポリシー言語 | 学習コスト | 表現力 | 再利用性 |
|:---:|:---:|:---:|:---:|:---:|
| **safe-docker** | TOML設定 + Rustコード | 低(設定) / 高(ロジック変更) | 中 | 低 |
| **permissions-hook** | TOML (regex) | 低 | 低〜中 | 中 |
| **OPA** | Rego | 高 | 非常に高 | 高 |
| **Kyverno** | YAML + CEL | 低〜中 | 高 | 高 |
| **PSA** | プリセット選択 | 非常に低 | 低 | N/A |
| **Falco** | YAML (条件式) | 中 | 高 | 高 |
| **KubeArmor** | YAML | 低 | 中 | 中 |

### 6.3 safe-docker のポジショニング

```
  デプロイ容易性
  高 ┃ ★ safe-docker     ★ PSA
     ┃ ★ permissions-hook
     ┃                        ★ Kyverno   ★ Docker ECI
     ┃               ★ OPA AuthZ   ★ Gatekeeper
     ┃                    ★ Falco  ★ KubeArmor
     ┃ ★ E2B (SaaS)                     ★ gVisor
  低 ┃                                        ★ Kata/Firecracker
     ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
     低                バイパス耐性                高
```

safe-docker は「デプロイ容易性が極めて高いが、バイパス耐性が低い」象限に位置する。これは設計上のトレードオフであり、ターゲットが「協調的なエージェント」であることを考慮すると合理的である。ただし、OPA Docker AuthZ との二層構成（README に記載済み）でバイパス耐性を補完する設計は的確。

---

## 7. 各アプローチから得られる設計パターンと safe-docker への適用可能性

### 7.1 PSA から: プロファイル方式

**パターン**: 事前定義のセキュリティプロファイルを提供し、ユーザーは個別ルールを理解しなくても適切なレベルを選択できる。

**適用**: safe-docker の設定に `profile = "strict" | "standard" | "permissive"` を導入。

| プロファイル | 説明 |
|---|---|
| strict | $HOME 配下のみ許可、全危険フラグブロック、イメージホワイトリスト必須 |
| standard | 現在のデフォルト設定相当 |
| permissive | 危険フラグは ask、パス制限は $HOME 外のみ deny |

### 7.2 Gatekeeper から: 監査（Audit）モード

**パターン**: deny せずにログだけ記録する監査モード。ポリシー導入の初期段階や、エージェントの行動パターンの可視化に有用。

**適用**: safe-docker に `mode = "enforce" | "audit" | "warn"` を追加。audit モードでは全判定をログに記録するが、コマンド実行はブロックしない。

### 7.3 Kyverno から: Mutate（変更）パターン

**パターン**: 拒否するだけでなく、安全な形に自動修正する。

**適用例**: `docker run ubuntu` に自動的に `--read-only --cap-drop=ALL --security-opt=no-new-privileges` を付加する「セキュアデフォルト注入」。ただし、Claude Code の hook プロトコルが現状 allow/deny/ask のみなので、コマンド書き換えの実装可能性を確認する必要がある。

### 7.4 Falco から: 構造化ルール + 例外メカニズム

**パターン**: ルールに対して宣言的な例外を定義できる仕組み。マクロ/リストによる DRY なルール管理。

**適用**: 設定ファイルで「このプロジェクトでは `--network=host` を許可」のようなルール単位の例外を宣言的に記述可能にする。

### 7.5 Cilium/Hubble から: 構造化監査ログ

**パターン**: セキュリティ判定を構造化 JSON で記録し、事後分析・可視化を可能にする。

**適用**: 全ての deny/ask/allow 判定を構造化 JSON でファイルに出力する監査ログ機能。

### 7.6 E2B/gVisor から: ランタイム隔離との統合

**パターン**: フィルタリングだけでなく、コンテナ自体の隔離レベルを向上させる。

**適用**: safe-docker が Docker rootless モードの使用を推奨・検出し、rootful Docker 使用時に警告する機能。

---

## 8. safe-docker への改善提案

調査結果を踏まえ、以下の改善を優先度順に提案する。

### Priority 1: 運用性の向上

#### P1-1. 監査（Audit）モード
**根拠**: OPA Gatekeeper, Kyverno, PSA の全てが Audit モードを実装している。ポリシー導入時の「まず様子を見る」フェーズは、ユーザーの信頼獲得に不可欠。

**実装案**: `config.toml` に `mode = "enforce" | "audit"` を追加。audit モードでは deny/ask 判定をログ出力するが、実際の判定は常に allow を返す。

#### P1-2. 構造化監査ログ
**根拠**: Falco, Cilium/Hubble, OPA の決定ログに共通する設計パターン。事後分析と可視化の基盤となる。

**実装案**: `~/.local/share/safe-docker/audit.jsonl` に JSON Lines 形式で出力。

```json
{"timestamp":"2025-01-15T10:30:00Z","decision":"deny","reason":"bind_mount_outside_home","command":"docker run -v /etc:/data ubuntu","paths":["/etc"],"flags":[]}
```

#### P1-3. セキュリティプロファイル（プリセット）
**根拠**: PSA の Privileged/Baseline/Restricted パターン。ユーザーが個別設定を理解しなくても安全な構成を選べる。

**実装案**: `config.toml` で `profile = "strict" | "standard" | "permissive"` を指定すると、対応するデフォルト値が適用される。個別設定でオーバーライド可能。

### Priority 2: ポリシーの柔軟性

#### P2-1. プロジェクト固有の設定ファイル
**根拠**: Kyverno の ClusterPolicy/Policy（スコープの分離）、`.claude/settings.json` のプロジェクトローカル設定。

**実装案**: プロジェクトルートの `.safe-docker.toml` をグローバル設定にマージ。グローバル設定が最低限の安全性を保証し、プロジェクト設定は「さらに制限」または「特定パスの追加許可」のみを許す（セキュリティレベルを緩めることはできない設計）。

#### P2-2. ルール単位の例外メカニズム
**根拠**: Falco の exceptions、KubeArmor の allow ルール。ブロックルールへの宣言的例外は現場で頻出するニーズ。

**実装案**:
```toml
# グローバルでは --network=host をブロック
blocked_flags = ["--network=host"]

# このプロジェクトでは例外的に許可
[exceptions]
allow_flags = ["--network=host"]
reason = "E2E テストで必要"
```

#### P2-3. コマンド書き換え（Mutate）機能の検討
**根拠**: Kyverno の Mutate パターン、Kubernetes の DefaultServiceAccount 自動注入。

**検討事項**: Claude Code の hook プロトコルが `decision` のみを返す設計のため、コマンド書き換えは hook プロトコルの制約を受ける。現時点で実装可能かを hook の仕様を詳細に確認する必要がある。実装不可の場合、deny メッセージに「安全なコマンド例」を含めることで間接的に同じ効果を狙う。

### Priority 3: セキュリティの深化

#### P3-1. Docker Rootless モードの検出・推奨
**根拠**: Docker Rootless は追加ツール不要でコンテナのセキュリティを大幅に向上させる。E2B/gVisor の「隔離」思想の最も手軽な実装。

**実装案**: Docker ソケットのパス（`$XDG_RUNTIME_DIR/docker.sock` vs `/var/run/docker.sock`）から rootless/rootful を判定し、rootful 使用時に初回のみ情報メッセージを出力。

#### P3-2. イメージ出自の検証（Image Provenance）
**根拠**: Kyverno の verifyImages、Sigstore/Cosign エコシステム。サプライチェーン攻撃への対策。

**実装案**: 設定で `require_signed_images = true` を有効にすると、`cosign verify` が通らないイメージの使用を ask にする。ただし、実装コストが高いため長期目標とする。

#### P3-3. Docker API レベルの監視（Layer 2 強化）
**根拠**: OPA Docker AuthZ の設計。hook バイパスへの対策。

**実装案**: 既存の OPA ポリシー（`opa/authz.rego`）をより詳細にし、safe-docker のルールセットと同等のカバレッジを Docker API レベルでも実現する。safe-docker 側に OPA ポリシーの自動生成機能を追加する（safe-docker の設定から Rego ポリシーを生成）。

### Priority 4: 長期的な発展

#### P4-1. 宣言的ポリシー言語の導入
**根拠**: OPA/Rego, Kyverno/YAML, ValidatingAdmissionPolicy/CEL の成功。ポリシーロジックをコードから設定に移行することで、ユーザーがルールをカスタマイズ可能になる。

**検討**: Rego は学習コストが高い。CEL は軽量で高速だが Rust からの利用に追加依存が必要。YAML パターンマッチ（Kyverno 方式）が safe-docker のユーザー層には最適かもしれない。レイテンシへの影響を慎重に評価する必要がある。

#### P4-2. テレメトリーと可視化ダッシュボード
**根拠**: Cilium/Hubble, Falco の UI。ポリシー判定の可視化はセキュリティ運用の要。

**実装案**: 監査ログを基に、CLI で簡易的な統計レポートを生成する `safe-docker stats` コマンド。

#### P4-3. エージェント行動の学習ベース分析
**根拠**: ProSPEC の予測モデル。AGrail の適応的ポリシー。

**将来構想**: 監査ログからエージェントの Docker 操作パターンを学習し、「通常パターンからの逸脱」を検出する異常検知。ただし、safe-docker の「シンプルさ」「低レイテンシ」という設計原則との整合性を慎重に検討する。

---

## 9. まとめ

safe-docker は「コーディングエージェントの Docker 操作を安全にフィルタリングする」という、比較的ニッチだが急速に重要性が増している領域のツールである。

**独自の価値**: 既存のセキュリティツールの多くは Kubernetes 環境を前提とし、カーネル権限や複雑なインフラを要求する。safe-docker は単一の Rust バイナリとして、個人開発環境で即座に利用可能であり、この「デプロイの容易さ」は他に類を見ない。

**設計上の正しい判断**:
- Fail-safe 原則（Gatekeeper, PSA と同じ）
- 二層防御（safe-docker + OPA AuthZ）の設計
- 構造化された Docker CLI パーサーによる堅牢な解析

**改善の最優先事項**: 監査モードと構造化ログの追加。これにより、ポリシーの段階的導入とエージェント行動の可視化が可能になり、ユーザーの信頼獲得と運用のフィードバックループが確立される。

---

## 参考リンク

### プロジェクト
- [OPA Docker AuthZ](https://github.com/open-policy-agent/opa-docker-authz)
- [Casbin Docker AuthZ Plugin](https://github.com/casbin/casbin-authz-plugin)
- [Docker Enhanced Container Isolation](https://docs.docker.com/enterprise/security/hardened-desktop/enhanced-container-isolation/)
- [OPA Gatekeeper](https://open-policy-agent.github.io/gatekeeper/)
- [Kyverno](https://kyverno.io/)
- [Falco](https://falco.org/)
- [KubeArmor](https://github.com/kubearmor/KubeArmor)
- [Cilium / Tetragon](https://github.com/cilium/tetragon)
- [E2B](https://e2b.dev/)
- [OpenHands](https://github.com/OpenHands/OpenHands)
- [claude-code-permissions-hook](https://github.com/kornysietsma/claude-code-permissions-hook)
- [gVisor](https://github.com/google/gvisor)
- [Kata Containers](https://katacontainers.io/)
- [Firecracker](https://github.com/firecracker-microvm/firecracker)
- [Docker Rootless Mode](https://docs.docker.com/engine/security/rootless/)
- [Awesome Sandbox (AI Code Sandboxing)](https://github.com/restyler/awesome-sandbox)
- [AI Agent Sandbox Comparison](https://dev.to/agentsphere/choosing-a-workspace-for-ai-agents-the-ultimate-showdown-between-gvisor-kata-and-firecracker-b10)

### 学術論文
- [A Container Security Survey: Exploits, Attacks, and Defenses (ACM Computing Surveys, 2024)](https://dl.acm.org/doi/10.1145/3715001)
- [Container Security: Precaution levels, mitigation strategies, and research perspectives (Computers and Security, 2023)](https://www.sciencedirect.com/science/article/abs/pii/S0167404823004005)
- [ProSPEC: Proactive Security Policy Enforcement for Containers (ACM CODASPY 2022)](https://dl.acm.org/doi/abs/10.1145/3508398.3511515)
- [PerfSPEC: Performance Profiling-Based Proactive Security Policy Enforcement for Containers (IEEE, 2024)](https://ieeexplore.ieee.org/document/10577533/)
- [OpenHands: An Open Platform for AI Software Developers as Generalist Agents (arXiv:2407.16741)](https://arxiv.org/abs/2407.16741)
- [AGrail: A Lifelong Agent Guardrail (ACL 2025)](https://aclanthology.org/2025.acl-long.399.pdf)
- [Building a Foundational Guardrail for General Agentic Systems (arXiv, 2025)](https://arxiv.org/html/2510.09781v1)
- [Guardrails and Security for LLMs (Survey, 2024-2025)](https://llm-guardrails-security.github.io/)

### その他
- [Docker Authorization Plugin API](https://docs.docker.com/engine/extend/plugins_authorization/)
- [Kubernetes Admission Controllers](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [OPA/Gatekeeper vs Kyverno 比較](https://nirmata.com/2025/02/07/kubernetes-policy-comparison-kyverno-vs-opa-gatekeeper/)
- [eBPF Ecosystem Progress 2024-2025](https://eunomia.dev/blog/2025/02/12/ebpf-ecosystem-progress-in-20242025-a-technical-deep-dive/)
- [Container Runtime Security Comparative Insights 2025](https://accuknox.com/wp-content/uploads/Container_Runtime_Security_Tooling.pdf)
- [Claude Code Hooks ガイド](https://claude.com/blog/how-to-configure-hooks)
- [Top AI Code Sandbox Products](https://modal.com/blog/top-code-agent-sandbox-products)
