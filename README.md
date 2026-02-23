# safe-docker

Claude Code PreToolUse hook で Docker コマンドのバインドマウントを `$HOME` 配下のみに制限する。

## アーキテクチャ

二層構成で Docker 操作を保護:

1. **safe-docker** (Rust) — Claude Code PreToolUse hook。CLI引数を解析して拒否理由をフィードバック
2. **OPA Docker AuthZ** (Rego) — Docker デーモン認可プラグイン。全クライアントへの最終防衛線

```
[Claude Code] → [safe-docker hook] → [docker CLI] → [Docker daemon] → [OPA authz]
                 UXレイヤー:                          強制レイヤー:
                 具体的な拒否理由                       全クライアントに適用
```

## 検出対象

### バインドマウント
- `-v /host:/container[:opts]`
- `--volume /host:/container[:opts]`
- `--mount type=bind,source=/host,target=/container`
- `docker-compose.yml` の volumes (short/long syntax)

### 危険フラグ
- `--privileged`
- `--cap-add` (SYS_ADMIN, SYS_PTRACE, SYS_MODULE, SYS_RAWIO, ALL)
- `--security-opt apparmor=unconfined` / `seccomp=unconfined`
- `--pid=host`
- `--network=host`
- `--device`

### パス判定

| パス | 判定 |
|------|------|
| `$HOME` 配下 | **allow** |
| `$HOME/.ssh` 等の機密パス | **ask** (ユーザー確認) |
| `$HOME` 外 | **deny** |
| Docker ソケット | **deny** |
| 環境変数未展開 | **ask** |

## 設定

`~/.config/safe-docker/config.toml` (省略時はデフォルト値):

```toml
# $HOME 外で追加許可するパス
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

## ビルド

```bash
cargo build --release
cp target/release/safe-docker ~/.local/bin/
```

## テスト

```bash
cargo test
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

# allow: 非 docker コマンド (出力なし)
echo '{"tool_name":"Bash","tool_input":{"command":"ls -la /tmp"}}' | safe-docker
```

## OPA Docker AuthZ (Phase 2)

`opa/authz.rego` を `/etc/docker/config/authz.rego` にコピーし、opa-docker-authz プラグインをインストールして使用する。詳細は [opa-docker-authz](https://github.com/open-policy-agent/opa-docker-authz) を参照。

### リカバリ手順

OPA ポリシーで Docker がロックアウトされた場合:

```bash
# 1. プラグインを無効化
docker plugin disable opa-docker-authz

# 2. または daemon.json から authorization-plugins を削除して Docker 再起動
sudo systemctl restart docker
```
