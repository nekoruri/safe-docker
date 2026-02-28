# safe-docker

[![CI](https://github.com/nekoruri/safe-docker/actions/workflows/ci.yml/badge.svg)](https://github.com/nekoruri/safe-docker/actions/workflows/ci.yml)
[![Security Audit](https://github.com/nekoruri/safe-docker/actions/workflows/audit.yml/badge.svg)](https://github.com/nekoruri/safe-docker/actions/workflows/audit.yml)
[![codecov](https://codecov.io/gh/nekoruri/safe-docker/graph/badge.svg)](https://codecov.io/gh/nekoruri/safe-docker)

コーディングエージェントや開発者に **安全に Docker 操作権限を渡す**ためのセキュリティツール。

2つの動作モードを持つ:

- **Hook モード**: Claude Code PreToolUse hook として、エージェントの Docker コマンドを実行前に検証
- **Wrapper モード**: `docker` コマンドの直接置換として、開発者のうっかりミスを防止

## 背景と目的

コーディングエージェントに Docker を使わせると開発の自由度が大きく向上する一方、無制約な Docker 操作はホストシステムへの重大なリスクとなる。safe-docker は「使わせない」のではなく「安全に使わせる」ことを目指し、Docker 操作に適切なガードレールを設ける。

### 守りたいもの

- **ホストファイルシステム**: エージェントの作業領域（`$HOME`）外のファイルへのアクセス防止
- **ホストの特権**: コンテナからのホスト特権昇格の防止
- **Docker デーモン**: Docker ソケット経由のデーモン操作の防止
- **機密情報**: SSH 鍵、クラウド認証情報等の意図しない露出防止

### 設計思想

- **Fail-safe**: 判断できない場合はブロックまたはユーザー確認（deny / ask）
- **透明性**: 拒否時は具体的な理由をフィードバックし、自律的な修正を促す
- **設定可能**: プロジェクトの要件に応じて許可範囲を調整可能
- **低レイテンシ**: hook はユーザー体験に直結するため、全処理を 1ms 以下で完了

## アーキテクチャ

### Hook モード（Claude Code 連携）

Claude Code PreToolUse hook として動作し、stdin/stdout の JSON プロトコルでコマンド実行前に検証する。

```
[Claude Code] → [safe-docker hook] → [docker CLI] → [Docker daemon]
                 stdin JSON で受信        ↑
                 deny/ask/allow を返す     |
                                    拒否理由をエージェントに返す
```

### Wrapper モード（docker 置換）

`docker` コマンドの代わりに使用し、ポリシーチェック後に本物の docker を `exec` で実行する。

```
[ユーザー/スクリプト] → [safe-docker] → ポリシー評価 → [本物の docker]
                         ↓                              ↑
                    allow → exec で置換（プロセス数増加なし）
                    deny  → stderr にエラー + exit 1
                    ask   → 対話的確認 (y/N)
```

### OPA Docker AuthZ（Layer 2）

OPA Docker AuthZ プラグインを最終防衛線として併用可能。safe-docker はエージェントに「なぜダメか」を伝える UX レイヤーであり、OPA は設定ミスや hook 回避への強制レイヤーとなる。

## 制限する操作

### 1. バインドマウントの制限

エージェントの作業領域（`$HOME`）外へのバインドマウントをブロックする。

| パス | 判定 | 例 |
|------|------|----|
| `$HOME` 配下 | **allow** | `-v ~/projects:/app` |
| `$HOME` 配下の機密パス | **ask** (ユーザー確認) | `-v ~/.ssh:/keys` |
| `$HOME` 外 | **deny** | `-v /etc:/data` |
| Docker ソケット | **deny** | `-v /var/run/docker.sock:/sock` |
| 環境変数未展開 | **ask** | `-v $MYVAR:/data` |

対応する構文:
- `-v` / `--volume` (short syntax)
- `--mount type=bind,source=...,target=...`
- `docker-compose.yml` の volumes (short/long syntax, `.env` 変数展開対応)
- `driver_opts.device` によるバインドマウント偽装

### 2. 危険フラグのブロック

コンテナからホスト特権を取得しうるフラグをブロックする。

| フラグ | リスク |
|--------|--------|
| `--privileged` | ホストデバイスへの完全アクセス |
| `--cap-add SYS_ADMIN` 等 | 危険な Linux capability の付与 |
| `--security-opt apparmor=unconfined` | セキュリティプロファイルの無効化 |
| `--security-opt seccomp=unconfined` | システムコールフィルタの無効化 |
| `--security-opt label=disable` | SELinux ラベリングの無効化 (CIS 5.2) |
| `--pid=host` | ホストの PID 名前空間へのアクセス |
| `--network=host` | ホストのネットワークスタックへのアクセス |
| `--userns=host` | ホストのユーザー名前空間へのアクセス |
| `--cgroupns=host` | ホストの cgroup 名前空間へのアクセス |
| `--ipc=host` | ホストの IPC 名前空間へのアクセス |
| `--uts=host` | ホストの UTS 名前空間へのアクセス (CIS 5.11) |
| `--device` | ホストデバイスの直接マウント |
| `--volumes-from` | 他コンテナからの危険なマウント継承 (ask) |
| `--network=container:NAME` | 他コンテナのネットワーク名前空間への参加 |
| `--pid=container:NAME` | 他コンテナのプロセス名前空間への参加 |
| `--ipc=container:NAME` | 他コンテナの IPC 名前空間への参加 |
| `-v ...:shared` / `bind-propagation=shared` | マウント変更がホストに伝搬 |
| `--sysctl kernel.*` | カーネルパラメータの操作 |
| `--sysctl net.*` | ネットワーク設定の変更 (ask) |
| `--add-host HOST:169.254.169.254` | クラウドメタデータエンドポイントへの参照 (ask) |
| `--env-file PATH` / `--label-file PATH` | $HOME 外のホストファイル読み取り |
| `--build-arg SECRET=...` | ビルド引数に機密情報パターン (ask) |
| `--secret src=PATH` / `--ssh src=PATH` | BuildKit ソースパスの $HOME 外アクセス |

### 3. シェル間接実行の検出（Hook モードのみ）

直接の `docker` コマンド以外にも、シェル経由の間接実行を検出する。

- `eval "docker run ..."` — eval 経由
- `bash -c "docker run ..."` / `sh -c '...'` — サブシェル経由
- `sudo docker run ...` — sudo 経由
- `xargs docker ...` — xargs 経由
- 環境変数プレフィックス付き: `DOCKER_HOST=... docker run ...`

### 4. パストラバーサル防止

ファイルが存在しない場合でも `..` を含むパスを論理正規化し、`$HOME/../../etc` のような回避を防ぐ。

### 5. docker cp / docker build のパス検証

`docker cp` と `docker build` で指定されるホストパスに対しても、バインドマウントと同じパス検証を適用する。

- `docker cp /etc/passwd container:/tmp` → **deny**（`$HOME` 外）
- `docker build -t myapp /etc` → **deny**（`$HOME` 外のコンテキスト）
- `docker build -t myapp ~/project` → **allow**

### 6. Compose ファイルの危険設定検出

`docker-compose.yml` のサービス定義から危険な設定を検出する。

- `privileged: true` → **deny**
- `network_mode: host` / `container:NAME` → **deny**
- `pid: host` / `container:NAME` → **deny**
- `ipc: host` / `container:NAME` → **deny**
- `userns_mode: host` → **deny**
- `uts: host` → **deny**
- `cap_add: [SYS_ADMIN, ...]` → **deny**（blocked_capabilities に該当するもの）
- `security_opt: [apparmor:unconfined, ...]` → **deny**
- `devices: [/dev/sda]` → **deny**
- `sysctls: kernel.*` → **deny** / `net.*` → **ask**
- `env_file: /etc/secrets.env` → **deny**（$HOME 外パス）
- `include: [/opt/shared/compose.yml]` → **ask**（$HOME 外パス）

### 7. イメージホワイトリスト（オプション）

設定により、使用可能な Docker イメージを制限できる。

## インストール

### GitHub Releases からダウンロード（推奨）

[Releases ページ](https://github.com/nekoruri/safe-docker/releases/latest) からプラットフォームに合ったバイナリをダウンロード:

```bash
# GitHub CLI でダウンロード + 検証
gh release download --repo nekoruri/safe-docker \
  --pattern "safe-docker-*-x86_64-unknown-linux-gnu.tar.gz"

# アーティファクトの署名を検証 (Sigstore ベース)
gh attestation verify safe-docker-*-x86_64-unknown-linux-gnu.tar.gz \
  --repo nekoruri/safe-docker

# 展開・配置
tar xzf safe-docker-*-x86_64-unknown-linux-gnu.tar.gz
cp safe-docker-*/safe-docker ~/.local/bin/
```

> リリースバイナリには GitHub Artifact Attestations (Sigstore ベース) による署名済みビルド証明が付与されています。
> 検証の仕組みについては [docs/SUPPLY_CHAIN_SECURITY.md](docs/SUPPLY_CHAIN_SECURITY.md) を参照してください。

<details>
<summary>各プラットフォームのダウンロード URL</summary>

| プラットフォーム | パターン |
|----------------|---------|
| Linux (x86_64) | `safe-docker-*-x86_64-unknown-linux-gnu.tar.gz` |
| Linux (aarch64) | `safe-docker-*-aarch64-unknown-linux-gnu.tar.gz` |
| macOS (Apple Silicon) | `safe-docker-*-aarch64-apple-darwin.tar.gz` |
| macOS (Intel) | `safe-docker-*-x86_64-apple-darwin.tar.gz` |

</details>

### ソースからビルド

```bash
# Git リポジトリから直接インストール
cargo install --git https://github.com/nekoruri/safe-docker.git

# またはクローンしてビルド
git clone https://github.com/nekoruri/safe-docker.git
cd safe-docker
cargo build --release
cp target/release/safe-docker ~/.local/bin/
```

## セットアップ

### Hook モード（Claude Code 連携）

Claude Code の設定 (`~/.claude/settings.json`) に hook を登録:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "safe-docker"
          }
        ]
      }
    ]
  }
}
```

### Wrapper モード（docker 置換）

#### 方法 1: 明示的に使用

```bash
safe-docker run -v ~/projects:/app ubuntu
safe-docker compose up
```

#### 方法 2: setup コマンドで透過的に置換（推奨）

`safe-docker setup` を実行すると、シンボリックリンクの作成と PATH の確認を自動で行う:

```bash
safe-docker setup
# → ~/.local/bin/docker -> safe-docker へのシンボリックリンクを作成
# → PATH の設定状況を確認し、必要に応じてアドバイスを表示

# ターゲットディレクトリを指定
safe-docker setup --target ~/bin

# 既存のシンボリックリンクを置換
safe-docker setup --force
```

以降、`docker` コマンドが safe-docker 経由で実行される:

```bash
docker run -v /etc:/data ubuntu
# → [safe-docker] BLOCKED: Path is outside $HOME ...
```

safe-docker は `argv[0]` が `docker` の場合に透過モードとして動作し、本物の docker バイナリを自動検索して `exec` で置換する。

#### 方法 3: 手動でシンボリックリンクを作成

```bash
ln -s $(which safe-docker) ~/.local/bin/docker
```

#### 方法 4: シェルエイリアス

```bash
alias docker='safe-docker'
```

> **Note**: エイリアスは interactive シェルでのみ有効。スクリプト内では方法 2 のシンボリックリンクを推奨。

## 使い方

### Wrapper モード

```bash
# 基本: 通常の docker コマンドと同じ引数
safe-docker run -v ~/projects:/app ubuntu echo hello
safe-docker compose up -d
safe-docker build -t myapp .

# --dry-run: ポリシー判定のみ表示（docker を実行しない）
safe-docker --dry-run run --privileged ubuntu
# → [safe-docker] Decision: deny

# --verbose: 拒否時に詳細な理由と対処法を表示
safe-docker --verbose run --privileged ubuntu
# → [safe-docker] BLOCKED: --privileged grants full host access ...
# →   Tip: Check ~/.config/safe-docker/config.toml to adjust allowed paths or flags

# --docker-path: docker バイナリパスを指定
safe-docker --docker-path /usr/bin/docker run ubuntu
```

### Hook モード

```bash
# deny: $HOME 外マウント
echo '{"tool_name":"Bash","tool_input":{"command":"docker run -v /etc:/data ubuntu"}}' | safe-docker

# allow: $HOME 配下マウント
echo '{"tool_name":"Bash","tool_input":{"command":"docker run -v ~/projects:/app ubuntu"}}' | safe-docker

# ask: 機密パス
echo '{"tool_name":"Bash","tool_input":{"command":"docker run -v ~/.ssh:/keys ubuntu"}}' | safe-docker

# deny: --privileged
echo '{"tool_name":"Bash","tool_input":{"command":"docker run --privileged ubuntu"}}' | safe-docker

# allow: 非 docker コマンド (出力なし)
echo '{"tool_name":"Bash","tool_input":{"command":"ls -la /tmp"}}' | safe-docker
```

### 設定チェック

```bash
safe-docker --check-config
safe-docker --check-config --config /path/to/config.toml
```

## 設定

`~/.config/safe-docker/config.toml` (省略時はデフォルト値):

```toml
# $HOME 外で追加許可するパス (プロジェクトのデータディレクトリ等)
allowed_paths = []

# $HOME 配下で ask にする機密パス (ホームからの相対)
sensitive_paths = [".ssh", ".aws", ".gnupg", ".docker", ".kube", ".config/gcloud", ".claude", ".terraform", ".vault-token", ".config/gh", ".npmrc", ".pypirc"]

# ブロックする危険フラグ
blocked_flags = ["--privileged", "--pid=host", "--network=host"]

# ブロックする capability
blocked_capabilities = ["SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO", "ALL", "DAC_READ_SEARCH", "NET_ADMIN", "BPF", "PERFMON", "SYS_BOOT"]

# イメージホワイトリスト (空=制限なし)
allowed_images = []

# Docker ソケットマウントの禁止
block_docker_socket = true

# 監査ログ設定
[audit]
enabled = false
format = "jsonl"       # "jsonl", "otlp", "both"
jsonl_path = "~/.local/share/safe-docker/audit.jsonl"
otlp_path = "~/.local/share/safe-docker/audit-otlp.jsonl"

# ラッパーモード設定
[wrapper]
docker_path = ""              # 本物の docker バイナリパス (空=自動検出)
non_interactive_ask = "deny"  # 非対話環境での ask 判定の扱い ("deny" / "allow")
```

## 環境変数

| 変数 | 説明 |
|------|------|
| `SAFE_DOCKER_DOCKER_PATH` | 本物の docker バイナリパスを指定（設定ファイルより優先） |
| `SAFE_DOCKER_ASK` | 非対話環境での ask 判定の扱い (`deny` / `allow`) |
| `SAFE_DOCKER_BYPASS` | `1` に設定するとポリシーチェックをスキップ（escape hatch） |
| `SAFE_DOCKER_ACTIVE` | 内部用: 再帰呼び出し防止。safe-docker が自動設定 |
| `SAFE_DOCKER_AUDIT` | `1` に設定すると設定ファイルに関わらず監査ログを有効化 |
| `SAFE_DOCKER_ENV` | 監査ログの `environment` フィールド（デフォルト: `development`） |

## セキュリティモデル

| | Hook モード | Wrapper モード |
|---|---|---|
| 対象 | AI エージェント | 人間の開発者 |
| 回避可能性 | 低（Claude Code が hook を迂回しにくい） | 高（`/usr/bin/docker` を直接呼べる） |
| 目的 | **強制的な安全装置** | **うっかりミスの防止** |
| Ask の意味 | Claude Code がユーザーに確認を促す | ユーザー自身に確認を求める |

Wrapper モードは「完全な強制」ではなく「安全ネット」。`SAFE_DOCKER_BYPASS=1` で意図的にスキップできるのは設計上正しい。完全な強制が必要な場合は OPA Docker AuthZ プラグイン等の別レイヤーで対応。

## ディレクトリ構成

```
src/
├── main.rs            # エントリポイント、モード判別（Hook/Wrapper）
├── wrapper.rs         # Wrapper モード（ポリシー評価、docker exec、対話的確認）
├── hook.rs            # Hook モード（stdin/stdout JSON プロトコル、Decision 型）
├── shell.rs           # シェルコマンドのパース（Hook モードで使用）
├── docker_args.rs     # Docker CLI 引数のパース（両モード共通）
├── path_validator.rs  # パス検証（両モード共通）
├── policy.rs          # ポリシー評価（両モード共通）
├── compose.rs         # docker-compose.yml の解析（両モード共通）
├── config.rs          # TOML 設定ファイル（[wrapper] / [audit] セクション含む）
├── setup.rs           # setup サブコマンド（シンボリックリンク作成、PATH 確認）
├── audit.rs           # 監査ログ（JSONL / OTLP、mode フィールドで Hook/Wrapper を区別）
├── error.rs           # エラー型定義
└── test_utils.rs      # テスト用ユーティリティ（TempEnvVar, ENV_MUTEX）

tests/
├── integration_test.rs    # Hook モードの E2E テスト
├── wrapper_test.rs        # Wrapper モードの E2E テスト
├── security_test.rs       # セキュリティバイパス検出テスト
├── proptest_test.rs       # ランダム入力によるクラッシュ耐性テスト
└── opa_consistency_test.rs  # OPA authz.rego との一貫性検証テスト

benches/
└── benchmark.rs         # criterion ベンチマーク
```

## テスト

```bash
# 全テスト実行 (ユニット + 統合 + セキュリティ + proptest)
cargo test

# ベンチマーク
cargo bench

# 静的解析
cargo clippy -- -D warnings
```

## OPA Docker AuthZ (Layer 2)

`opa/authz.rego` を `/etc/docker/config/authz.rego` にコピーし、opa-docker-authz プラグインをインストールして使用する。詳細は [opa-docker-authz](https://github.com/open-policy-agent/opa-docker-authz) を参照。

### リカバリ手順

OPA ポリシーで Docker がロックアウトされた場合:

```bash
# 1. プラグインを無効化
docker plugin disable opa-docker-authz

# 2. または daemon.json から authorization-plugins を削除して Docker 再起動
sudo systemctl restart docker
```

## ライセンス

MIT OR Apache-2.0 のデュアルライセンスで提供されています。詳細は [LICENSE-MIT](LICENSE-MIT) および [LICENSE-APACHE](LICENSE-APACHE) を参照してください。
