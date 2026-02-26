# セキュリティモデル

## 脅威モデル

### 攻撃者

コーディングエージェント（Claude Code 等）が、意図的または非意図的に、ホストシステムへの不正アクセスを試みるケースを想定する。

攻撃者の能力:
- Bash ツールを通じて任意のシェルコマンドを実行できる
- Write ツールを通じて任意のファイルを作成・変更できる
- 複数ステップにわたる攻撃を計画・実行できる

### 守りたいもの

| 資産 | 脅威 | 対策 |
|------|------|------|
| ホストファイルシステム | `$HOME` 外のファイル読み書き | バインドマウント、docker cp、docker build のパス検証 |
| ホスト特権 | コンテナからのエスケープ | `--privileged`、危険 capability、namespace フラグのブロック |
| Docker デーモン | ソケット経由の制御奪取 | Docker ソケットマウントのブロック |
| 機密情報 | SSH 鍵、クラウド認証情報の露出 | `$HOME` 配下の機密パスを ask 判定 |

## 防御レイヤー

### Layer 1: safe-docker (UX レイヤー)

Claude Code PreToolUse hook として動作。コマンド実行前に検証し、拒否時は理由をエージェントにフィードバックする。

**特性**:
- エージェントに「なぜダメか」を伝え、自律的な修正を促す
- 設定で許可範囲を調整可能
- hook のため、エージェント以外のクライアントには適用されない

### Layer 2: OPA Docker AuthZ (強制レイヤー)

Docker デーモンの認可プラグイン。全 Docker クライアントに適用される最終防衛線。

**特性**:
- safe-docker の設定ミスや hook 回避をカバー
- daemon レベルで全リクエストを検査
- safe-docker が停止していても機能する

## 既知の制限事項

### 構造的な制限（hook の制約）

| 制限 | リスク | 緩和策 |
|------|--------|--------|
| **スクリプトファイル経由のバイパス** | Write でスクリプトを作成し `bash script.sh` で実行すると、hook はスクリプト内の docker コマンドを検査できない | Layer 2 (OPA) で防御。Write hook との連携を検討中 |
| **エイリアス/関数** | `alias d=docker` や shell 関数経由の実行は検出困難 | Layer 2 (OPA) で防御 |
| **バイナリ実行** | コンパイルされたバイナリ内から docker CLI/API を呼ぶケース | Layer 2 (OPA) で防御 |
| **Docker API 直接呼び出し** | ソケットや TCP で直接 API を叩くケース | Docker ソケットマウントのブロック + Layer 2 |

### パーサーの制限

| 制限 | リスク | 緩和策 |
|------|--------|--------|
| **シェル変数展開** | `$CMD` に docker コマンドが格納されている場合、内容を検査できない | 変数展開を含むパスは ask (ユーザー確認) |
| **ヒアドキュメント** | `docker run <<EOF ... EOF` のようなパターンは未対応 | 稀なパターンのため優先度低 |
| **複雑なシェル構文** | 関数定義内、case 文内等の docker コマンドは検出困難 | 一般的なパターンのみカバー |

### 未検出の攻撃ベクトル（CLI レベルで対応可能、今後対応予定）

| 項目 | 状態 | リスク |
|------|------|--------|
| **`--uts=host`** | **検出済み (v0.5.0)** | ホスト名変更によるネットワーク攻撃（CIS 5.11） |
| **`--env-file PATH`** | **検出済み (v0.5.0)** | ホスト上の任意ファイル内容を環境変数として読み取り |
| **`--label-file PATH`** | **検出済み (v0.5.0)** | 同上 |
| **`--security-opt seccomp=PATH`** | **検出済み (v0.5.0)** | `$HOME` 外の seccomp プロファイル読み取り |
| **`--cap-add DAC_READ_SEARCH`** | **ブロック済み (v0.5.0)** | ファイル読み取り権限バイパス |
| **`--cap-add NET_ADMIN`** | **ブロック済み (v0.5.0)** | ネットワーク完全制御 |
| **`--cap-add BPF`** | **ブロック済み (v0.5.0)** | eBPF プログラムロード |
| **`--cap-add PERFMON`** | **ブロック済み (v0.5.0)** | パフォーマンスモニタリング（サイドチャネル攻撃） |
| **`--cap-add SYS_BOOT`** | **ブロック済み (v0.5.0)** | ホスト再起動 |
| **`--sysctl kernel.*`** | **検出済み (v0.5.0)** | カーネルパラメータ操作 → deny |
| **`--sysctl net.*`** | **検出済み (v0.5.0)** | ネットワーク設定変更 → ask |
| **`--add-host` メタデータ IP** | **検出済み (v0.5.0)** | 169.254.169.254 / fd00:ec2::254 → ask |
| **`--security-opt label=disable`** | **検出済み (v0.5.0)** | SELinux ラベリング無効化（CIS 5.2） → deny |
| **`--build-arg SECRET/PASSWORD/TOKEN`** | **検出済み (v0.5.0)** | ビルド引数に機密情報パターン → ask |
| **`--secret src=PATH`** | **検出済み (v0.5.0)** | BuildKit secret ソースパスの $HOME 外アクセス → deny |
| **`--ssh src=PATH`** | **検出済み (v0.5.0)** | BuildKit SSH ソースパスの $HOME 外アクセス → deny |
| **Compose `include:`** | **検出済み (v0.5.0)** | 外部ファイル参照の $HOME 外パス → ask |

> 詳細: [docs/ATTACK_SURFACE_ANALYSIS.md](docs/ATTACK_SURFACE_ANALYSIS.md)

### 検出されるが ask/deny できない項目

| 項目 | 状態 | 理由 |
|------|------|------|
| **名前付きボリュームのドライバ** | 未検出 | CLI レベルでは `docker volume create --driver=local --opt device=/etc` を事前に実行されると検出不能 |
| **bind propagation** | **検出済み (v0.4.0)** | `:shared`, `:rshared` は deny、`:slave` 等は許可 |
| **`DOCKER_HOST` 環境変数** | パス検証のみ | リモート Docker ホストへの接続自体はブロックしない（コマンド内容は検証する） |

## Fail-safe 設計

| 状況 | 判定 |
|------|------|
| stdin 読み取りエラー | **deny** |
| 入力が 256KB 超 | **deny** |
| JSON パースエラー | **deny** |
| パニック発生 | **deny** |
| 設定ファイル読み取りエラー | デフォルト設定で継続 |
| パス正規化失敗（ファイル非存在） | 論理正規化で判定 |
| 環境変数未展開 | **ask** (ユーザー確認) |
| Compose ファイルパースエラー | **deny** |
| Compose ファイル未検出 | **deny** |

## 検出対象一覧

### Docker CLI フラグ

| フラグ | 判定 | 対応構文 |
|--------|------|----------|
| `--privileged` | deny | |
| `--cap-add SYS_ADMIN` 等 | deny | スペース区切り、`=` 区切り |
| `--security-opt apparmor=unconfined` | deny | `=` 区切り、`:` 区切り |
| `--security-opt seccomp=unconfined` | deny | `=` 区切り、`:` 区切り |
| `--pid=host` | deny | `=` 区切り、スペース区切り |
| `--network=host` / `--net=host` | deny | `=` 区切り、スペース区切り |
| `--userns=host` | deny | `=` 区切り、スペース区切り |
| `--cgroupns=host` | deny | `=` 区切り、スペース区切り |
| `--ipc=host` | deny | `=` 区切り、スペース区切り |
| `--uts=host` | deny | `=` 区切り、スペース区切り |
| `--device` | deny | スペース区切り、`=` 区切り |
| `--volumes-from` | ask | スペース区切り、`=` 区切り |
| `--env-file PATH` | パス検証 | スペース区切り、`=` 区切り |
| `--label-file PATH` | パス検証 | スペース区切り、`=` 区切り |
| `--security-opt seccomp=PATH` | パス検証 | `unconfined` 以外のパスを検証 |
| `--security-opt label=disable` | deny | CIS 5.2: SELinux ラベリング無効化 |
| `--sysctl kernel.*` | deny | カーネルパラメータ操作 |
| `--sysctl net.*` | ask | ネットワーク設定変更 |
| `--add-host HOST:169.254.169.254` | ask | クラウドメタデータエンドポイント |
| `--build-arg KEY=VALUE` | ask | KEY に SECRET/PASSWORD/TOKEN 等のパターンを含む場合 |
| `--secret id=...,src=PATH` | パス検証 | BuildKit secret ソースパスの検証 |
| `--ssh id=...,src=PATH` | パス検証 | BuildKit SSH ソースパスの検証 |

### バインドマウント

| 構文 | 対応 |
|------|------|
| `-v host:container` | 対応 |
| `--volume host:container` | 対応 |
| `--volume=host:container` | 対応 |
| `--mount type=bind,source=...,target=...` | 対応 |
| `--mount=type=bind,source=...,target=...` | 対応 |
| Compose short syntax (`./src:/app`) | 対応 |
| Compose long syntax (`type: bind`) | 対応 |
| Compose `driver_opts.device` | 対応 |

### ホストパス検証

| コマンド | 対応 |
|----------|------|
| `docker run -v` / `--mount` | 対応 |
| `docker create -v` / `--mount` | 対応 |
| `docker cp` | 対応 |
| `docker build` (コンテキストパス) | 対応 |
| `docker compose` (compose ファイル解析) | 対応 |

### シェル間接実行

| パターン | 対応 |
|----------|------|
| `eval "docker ..."` | 対応 |
| `bash -c "docker ..."` | 対応 |
| `sh -c 'docker ...'` | 対応 |
| `zsh -c "docker ..."` | 対応 |
| `/bin/bash -c "docker ..."` | 対応 |
| `sudo eval "docker ..."` | 対応 |
| `sudo bash -c "docker ..."` | 対応 |
| `xargs docker ...` | 対応 |

### Compose 危険設定

| 設定 | 判定 |
|------|------|
| `privileged: true` | deny |
| `network_mode: host` | deny |
| `pid: host` | deny |
| `userns_mode: host` | deny |
| `ipc: host` | deny |
| `uts: host` | deny |
| `cap_add: [SYS_ADMIN, ...]` | deny (blocked capabilities) |
| `security_opt: [apparmor:unconfined, ...]` | deny |
| `devices: [/dev/...]` | deny |
| `sysctls: kernel.*` | deny |
| `sysctls: net.*` | ask |
| `include:` (外部ファイル参照) | ask ($HOME 外パス) |

## 脆弱性報告

セキュリティ上の問題を発見した場合は、Issue で報告してください。
