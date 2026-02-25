# safe-docker

コーディングエージェント（Claude Code 等）に **安全に Docker 操作権限を渡す**ためのセキュリティツール。

## 背景と目的

コーディングエージェントに Docker を使わせると開発の自由度が大きく向上する一方、無制約な Docker 操作はホストシステムへの重大なリスクとなる。safe-docker は「使わせない」のではなく「安全に使わせる」ことを目指し、エージェントの Docker 操作に適切なガードレールを設ける。

### 守りたいもの

- **ホストファイルシステム**: エージェントの作業領域（`$HOME`）外のファイルへのアクセス防止
- **ホストの特権**: コンテナからのホスト特権昇格の防止
- **Docker デーモン**: Docker ソケット経由のデーモン操作の防止
- **機密情報**: SSH 鍵、クラウド認証情報等の意図しない露出防止

### 設計思想

- **Fail-safe**: 判断できない場合はブロックまたはユーザー確認（deny / ask）
- **透明性**: 拒否時は具体的な理由をエージェントにフィードバックし、自律的な修正を促す
- **設定可能**: プロジェクトの要件に応じて許可範囲を調整可能
- **低レイテンシ**: hook はユーザー体験に直結するため、全処理を 1ms 以下で完了

## アーキテクチャ

二層構成で Docker 操作を保護する:

1. **safe-docker** (Rust) — Claude Code PreToolUse hook。コマンド実行前に検証し、拒否理由をフィードバック
2. **OPA Docker AuthZ** (Rego) — Docker デーモン認可プラグイン。全クライアントへの最終防衛線

```
[Claude Code] → [safe-docker hook] → [docker CLI] → [Docker daemon] → [OPA authz]
                 UXレイヤー:                          強制レイヤー:
                 拒否理由をエージェントに返す            全クライアントに適用
```

safe-docker はエージェントに「なぜダメか」を伝えるUXレイヤーであり、OPA は設定ミスや hook 回避への最終防衛線となる。

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
| `--pid=host` | ホストの PID 名前空間へのアクセス |
| `--network=host` | ホストのネットワークスタックへのアクセス |
| `--userns=host` | ホストのユーザー名前空間へのアクセス |
| `--cgroupns=host` | ホストの cgroup 名前空間へのアクセス |
| `--ipc=host` | ホストの IPC 名前空間へのアクセス |
| `--device` | ホストデバイスの直接マウント |
| `--volumes-from` | 他コンテナからの危険なマウント継承 (ask) |

### 3. シェル間接実行の検出

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
- `network_mode: host` → **deny**
- `pid: host` → **deny**
- `cap_add: [SYS_ADMIN]` → **deny**
- `security_opt: [apparmor:unconfined]` → **deny**
- `devices: [/dev/sda]` → **deny**

### 7. イメージホワイトリスト（オプション）

設定により、使用可能な Docker イメージを制限できる。

## 設定

`~/.config/safe-docker/config.toml` (省略時はデフォルト値):

```toml
# $HOME 外で追加許可するパス (プロジェクトのデータディレクトリ等)
allowed_paths = []

# $HOME 配下で ask にする機密パス (ホームからの相対)
sensitive_paths = [".ssh", ".aws", ".gnupg", ".docker", ".kube", ".config/gcloud", ".claude"]

# ブロックする危険フラグ
blocked_flags = ["--privileged", "--pid=host", "--network=host"]

# ブロックする capability
blocked_capabilities = ["SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO", "ALL"]

# イメージホワイトリスト (空=制限なし)
allowed_images = []

# Docker ソケットマウントの禁止
block_docker_socket = true
```

## インストール

### GitHub Releases からダウンロード（推奨）

[Releases ページ](https://github.com/nekoruri/safe-docker/releases/latest) からプラットフォームに合ったバイナリをダウンロード:

```bash
# Linux (x86_64)
curl -L https://github.com/nekoruri/safe-docker/releases/latest/download/safe-docker-v0.1.0-x86_64-unknown-linux-gnu.tar.gz | tar xz
cp safe-docker-v0.1.0-x86_64-unknown-linux-gnu/safe-docker ~/.local/bin/

# Linux (aarch64)
curl -L https://github.com/nekoruri/safe-docker/releases/latest/download/safe-docker-v0.1.0-aarch64-unknown-linux-gnu.tar.gz | tar xz
cp safe-docker-v0.1.0-aarch64-unknown-linux-gnu/safe-docker ~/.local/bin/

# macOS (Apple Silicon)
curl -L https://github.com/nekoruri/safe-docker/releases/latest/download/safe-docker-v0.1.0-aarch64-apple-darwin.tar.gz | tar xz
cp safe-docker-v0.1.0-aarch64-apple-darwin/safe-docker ~/.local/bin/

# macOS (Intel)
curl -L https://github.com/nekoruri/safe-docker/releases/latest/download/safe-docker-v0.1.0-x86_64-apple-darwin.tar.gz | tar xz
cp safe-docker-v0.1.0-x86_64-apple-darwin/safe-docker ~/.local/bin/
```

### ソースからビルド

```bash
cargo build --release
cp target/release/safe-docker ~/.local/bin/
```

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

## テスト

```bash
# 全テスト実行 (ユニット + 統合 + セキュリティ + proptest)
cargo test

# ベンチマーク
cargo bench

# 静的解析
cargo clippy -- -D warnings
```

## 手動テスト

```bash
# deny: $HOME 外マウント
echo '{"tool_name":"Bash","tool_input":{"command":"docker run -v /etc:/data ubuntu"}}' | safe-docker

# allow: $HOME 配下マウント
echo '{"tool_name":"Bash","tool_input":{"command":"docker run -v ~/projects:/app ubuntu"}}' | safe-docker

# ask: 機密パス
echo '{"tool_name":"Bash","tool_input":{"command":"docker run -v ~/.ssh:/keys ubuntu"}}' | safe-docker

# deny: --privileged
echo '{"tool_name":"Bash","tool_input":{"command":"docker run --privileged ubuntu"}}' | safe-docker

# deny: シェル間接実行
echo '{"tool_name":"Bash","tool_input":{"command":"eval \"docker run -v /etc:/data ubuntu\""}}' | safe-docker

# allow: 非 docker コマンド (出力なし)
echo '{"tool_name":"Bash","tool_input":{"command":"ls -la /tmp"}}' | safe-docker
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
