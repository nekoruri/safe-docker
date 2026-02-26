# OPA Docker AuthZ 統合ガイド

safe-docker と OPA Docker AuthZ プラグインを組み合わせた多層防御の構成ガイド。

## 目次

- [safe-docker と OPA Docker AuthZ の関係](#safe-docker-と-opa-docker-authz-の関係)
- [OPA Docker AuthZ プラグインの概要](#opa-docker-authz-プラグインの概要)
- [統合パターン](#統合パターン)
- [OPA ポリシー例](#opa-ポリシー例)
- [セットアップ手順](#セットアップ手順)
- [トラブルシューティング](#トラブルシューティング)
- [safe-docker と OPA のポリシー差異](#safe-docker-と-opa-のポリシー差異)
- [ポリシーの一貫性検証](#ポリシーの一貫性検証)

---

## safe-docker と OPA Docker AuthZ の関係

safe-docker は Docker 操作に対するセキュリティガードレールだが、CLI レベルで動作するため、設計上の制限がある（[ROADMAP.md の設計メモ](ROADMAP.md#設計メモ) 参照）:

1. **スクリプトファイル経由のバイパス**: `bash script.sh` で実行されたスクリプト内の docker コマンドは検査できない
2. **Docker API 直接呼び出し**: curl や SDK で Docker ソケット/TCP 経由の API を直接叩かれると検出不能
3. **複雑なシェル構文**: 変数展開や関数定義を経由する docker コマンドは検出困難
4. **Wrapper モードの迂回**: `/usr/bin/docker` を直接呼べば safe-docker をスキップできる

これらの制限に対して、OPA Docker AuthZ プラグインは Docker **デーモンレベル**で全 API リクエストを検査するため、CLI の制限を補完できる。

### 2つのレイヤーの役割

| | Layer 1: safe-docker | Layer 2: OPA Docker AuthZ |
|---|---|---|
| **動作レイヤー** | CLI (コマンド実行前) | Docker デーモン (API リクエスト時) |
| **対象** | docker CLI 経由の操作 | **全ての** Docker API リクエスト |
| **UX** | 拒否理由をユーザー/エージェントにフィードバック | API エラーとして返却 |
| **バイパス耐性** | 低（CLI レベルのため迂回可能） | 高（デーモンレベルで強制） |
| **導入コスト** | バイナリ1つの配置 | デーモン設定変更 + プラグインインストール |
| **主な目的** | うっかりミスの防止、エージェントへの教育的フィードバック | 強制的なポリシー適用 |

safe-docker は「なぜその操作が危険か」をユーザーやエージェントに伝える **UX レイヤー** であり、OPA Docker AuthZ は設定ミスやバイパスに対する **強制レイヤー** である。両方を併用することで多層防御を実現する。

---

## OPA Docker AuthZ プラグインの概要

### Docker Authorization Plugin の仕組み

Docker デーモンには [Authorization Plugin API](https://docs.docker.com/engine/extend/plugins_authorization/) が組み込まれている。この API を使うと、Docker デーモンが受け取る **全ての API リクエスト** を外部プラグインに転送し、許可/拒否の判断を委譲できる。

```
クライアント → Docker デーモン → AuthZ プラグイン → 許可/拒否
  (docker CLI,       ↑                  ↓
   curl, SDK)    API レスポンス    ポリシー評価
```

プラグインには2つの呼び出しタイミングがある:

- **AuthZReq**: リクエスト受信時（コンテナ作成前に検査）
- **AuthZRes**: レスポンス返却時（結果のフィルタリング）

### OPA (Open Policy Agent)

[OPA](https://www.openpolicyagent.org/) は CNCF Graduated プロジェクトで、汎用のポリシーエンジン。Rego という宣言的なポリシー言語でルールを記述し、構造化データ (JSON) に対してポリシー評価を行う。Kubernetes (Gatekeeper)、API ゲートウェイ、CI/CD パイプラインなど、幅広いユースケースで利用されている。

### opa-docker-authz プラグイン

[opa-docker-authz](https://github.com/open-policy-agent/opa-docker-authz) は、Docker Authorization Plugin API と OPA を橋渡しするプラグイン。Docker のマネージドプラグイン (v2) として動作し、Docker デーモンがライフサイクルを管理する。

主な特徴:

- Docker API リクエストの全フィールドを Rego ポリシーで評価
- バインドマウントのシンボリックリンク自動解決（パストラバーサル防止）
- 決定ログの JSON 出力
- リモートバンドルによるポリシー配信（集中管理）

---

## 統合パターン

### パターン A: safe-docker のみ

```
[ユーザー/エージェント] → [safe-docker] → [docker CLI] → [Docker デーモン]
```

**特徴**:
- 導入が最も簡単（バイナリ1つの配置）
- 拒否時にユーザー/エージェントへ理由をフィードバック
- Docker CLI 経由の操作のみ保護（API 直接呼び出しは検出不能）

**適したユースケース**:
- 個人の開発ワークステーション
- Claude Code との連携（Hook モード）
- 素早く導入したい場合
- エージェントが協調的（意図的なバイパスを試みない）な環境

### パターン B: OPA Docker AuthZ のみ

```
[ユーザー/エージェント] → [docker CLI / curl / SDK] → [Docker デーモン] → [OPA AuthZ]
```

**特徴**:
- Docker デーモンレベルで全 API リクエストを強制的に検査
- CLI、SDK、curl など全ての経路をカバー
- ポリシー違反時の理由は Docker API エラーとして返却（エージェント向けの教育的メッセージはない）

**適したユースケース**:
- 共有サーバー（複数ユーザーが Docker を使用）
- 強制的なポリシー適用が必要な環境
- Docker API を直接呼び出すツールの利用がある環境

### パターン C: safe-docker + OPA Docker AuthZ（推奨）

```
[ユーザー/エージェント] → [safe-docker] → [docker CLI] → [Docker デーモン] → [OPA AuthZ]
                           Layer 1                            Layer 2
                         UX + 教育的FB                     強制的ポリシー
```

**特徴**:
- safe-docker が第1レイヤーとして、わかりやすい拒否理由をフィードバック
- OPA AuthZ が第2レイヤーとして、CLI バイパスやスクリプト経由の操作もブロック
- safe-docker を迂回されても OPA がバックストップとして機能

**適したユースケース**:
- コーディングエージェントが Docker を使う環境で最も堅牢な構成
- CI/CD 環境でエージェントに Docker を使わせる場合
- セキュリティ要件が高い開発環境

**ポリシーの一貫性**: safe-docker のポリシー（`config.toml`）と OPA のポリシー（`authz.rego`）で同等のルールを定義することで、Layer 1 で拒否されたものが Layer 2 でも確実にブロックされる。OPA 側のポリシーは safe-docker 側と同等かそれ以上に厳しく設定することを推奨する。

---

## OPA ポリシー例

safe-docker のポリシーと対応する OPA Rego ポリシーの例を示す。以下のポリシーは本リポジトリの [`opa/authz.rego`](../opa/authz.rego) をベースにしている。

### 基本構造

```rego
package docker.authz

import rego.v1

default allow := false

# プラグイン操作は常に許可（ロックアウト防止）
allow if {
    input.Path == "/Plugin.Disable"
}

allow if {
    input.Path == "/Plugin.Enable"
}

# deny ルールに引っかからなければ許可
allow if {
    not deny
}
```

> **重要**: プラグインの有効化/無効化は常に許可する。これを拒否すると、ポリシーに問題があった場合にプラグインを無効化できなくなり、Docker が完全にロックアウトされる。

### --privileged のブロック

safe-docker では `blocked_flags = ["--privileged"]` に対応:

```rego
# --privileged をブロック
deny if {
    input.Body.HostConfig.Privileged == true
}
```

Docker API では `--privileged` フラグは `HostConfig.Privileged` フィールドとして送信される。safe-docker が CLI 引数の `--privileged` を検出するのに対し、OPA は API リクエストボディの JSON フィールドを直接検査する。

### $HOME 外のバインドマウントの制限

safe-docker のパス検証（`$HOME` 配下のみ許可）に対応:

```rego
# バインドマウントパスを $HOME 配下のみに制限
# 注意: "/home/username/" を実際のユーザーのホームディレクトリに変更すること
deny if {
    bm := input.BindMounts[_]
    resolved := bm.Resolved
    resolved != ""
    not startswith(resolved, "/home/username/")
}

# シンボリックリンクによるパストラバーサルの検出
# Source が $HOME 配下でもリンク先が $HOME 外の場合をブロック
deny if {
    bm := input.BindMounts[_]
    startswith(bm.Source, "/home/username/")
    bm.Resolved != ""
    not startswith(bm.Resolved, "/home/username/")
}

# Docker ソケットのマウントを禁止
deny if {
    bm := input.BindMounts[_]
    bm.Resolved == "/var/run/docker.sock"
}
```

`opa-docker-authz` プラグインは `input.BindMounts` にシンボリックリンクを解決済みのパス (`Resolved`) を提供する。これにより、`$HOME/symlink -> /etc` のようなパストラバーサルも検出できる。

### 危険な capability の制限

safe-docker の `blocked_capabilities` に対応。本リポジトリの `opa/authz.rego` は safe-docker のデフォルトと同じリストを使用している（一貫性検証テスト `tests/opa_consistency_test.rs` で自動チェック）:

```rego
# 危険な capability をブロック
# safe-docker の default_blocked_capabilities() と同期すること
deny if {
    cap := input.Body.HostConfig.CapAdd[_]
    cap in {
        "SYS_ADMIN",
        "SYS_PTRACE",
        "SYS_MODULE",
        "SYS_RAWIO",
        "DAC_READ_SEARCH",
        "NET_ADMIN",
        "BPF",
        "PERFMON",
        "SYS_BOOT",
        "ALL",
    }
}
```

### 危険な名前空間フラグのブロック

safe-docker の `--pid=host`, `--network=host` 等に対応:

```rego
# ホストの名前空間へのアクセスをブロック
deny if { input.Body.HostConfig.PidMode == "host" }
deny if { input.Body.HostConfig.NetworkMode == "host" }
deny if { input.Body.HostConfig.IpcMode == "host" }
deny if { input.Body.HostConfig.UTSMode == "host" }
deny if { input.Body.HostConfig.CgroupnsMode == "host" }
deny if { input.Body.HostConfig.UsernsMode == "host" }
```

### デバイスアクセスのブロック

safe-docker の `--device` 検出に対応:

```rego
# デバイスアクセスをブロック
deny if {
    count(input.Body.HostConfig.Devices) > 0
}
```

### 危険な security-opt のブロック

safe-docker の `is_dangerous_security_opt()` に対応:

```rego
# 危険な security-opt をブロック
deny if { opt := input.Body.HostConfig.SecurityOpt[_]; contains(opt, "apparmor=unconfined") }
deny if { opt := input.Body.HostConfig.SecurityOpt[_]; contains(opt, "seccomp=unconfined") }
deny if { opt := input.Body.HostConfig.SecurityOpt[_]; contains(opt, "label=disable") }
deny if { opt := input.Body.HostConfig.SecurityOpt[_]; contains(opt, "label:disable") }
deny if { opt := input.Body.HostConfig.SecurityOpt[_]; contains(opt, "no-new-privileges=false") }
deny if { opt := input.Body.HostConfig.SecurityOpt[_]; contains(opt, "systempaths=unconfined") }
```

### ポリシーの対応表

以下に safe-docker の主要なポリシーと、対応する OPA Rego の検査対象フィールドをまとめる:

| safe-docker のポリシー | OPA (Docker API フィールド) |
|---|---|
| `--privileged` → deny | `HostConfig.Privileged == true` |
| `-v /etc:/data` → deny | `BindMounts[_].Resolved` のパス検査 |
| `--cap-add SYS_ADMIN` → deny | `HostConfig.CapAdd[_]` |
| `--pid=host` → deny | `HostConfig.PidMode == "host"` |
| `--network=host` → deny | `HostConfig.NetworkMode == "host"` |
| `--ipc=host` → deny | `HostConfig.IpcMode == "host"` |
| `--device /dev/sda` → deny | `HostConfig.Devices[_]` |
| `--security-opt apparmor=unconfined` → deny | `HostConfig.SecurityOpt[_]` |
| Docker ソケットマウント → deny | `BindMounts[_].Resolved == "/var/run/docker.sock"` |

---

## セットアップ手順

### 前提条件

- Docker Engine 18.09 以上
- OPA Docker AuthZ プラグイン v0.10 以上

### 1. OPA Docker AuthZ プラグインのインストール

プラグインは Docker のマネージドプラグインとして提供されている。`--alias` でローカルな短い名前を付けておくと、以降のコマンドや `daemon.json` での参照が簡潔になる。

```bash
# プラグインをインストール（TLS なしのローカル開発環境向け）
# --alias で短い名前を付与
docker plugin install --alias opa-docker-authz \
    openpolicyagent/opa-docker-authz-v2:0.10 \
    opa-args="-policy-file /opa/authz.rego"
```

プラグイン内部のパス `/opa/authz.rego` は、プラグインコンテナ内のファイルシステムパスを指す。ポリシーファイルの配置方法は次の手順を参照。

> 詳細なインストール手順（TLS 設定、リモートバンドル等）は [opa-docker-authz の公式ドキュメント](https://github.com/open-policy-agent/opa-docker-authz) を参照。

### 2. Rego ポリシーファイルの配置

本リポジトリの `opa/authz.rego` をプラグインが読み込む場所に配置する。マネージドプラグインはプラグインコンテナ内で動作するため、ポリシーファイルはプラグインのルートファイルシステムに配置する必要がある:

```bash
# プラグインのルートファイルシステムにコピー
# プラグイン ID は `docker plugin inspect` で確認
PLUGIN_ID=$(docker plugin inspect -f '{{.Id}}' opa-docker-authz)
sudo cp opa/authz.rego /var/lib/docker/plugins/${PLUGIN_ID}/rootfs/opa/authz.rego
```

`authz.rego` 内のホームディレクトリパス（サンプルでは `/home/username/`）を、実際のユーザーのホームディレクトリに変更すること:

```bash
# 例: ユーザー名が "alice" の場合
sudo sed -i 's|/home/username/|/home/alice/|g' \
    /var/lib/docker/plugins/${PLUGIN_ID}/rootfs/opa/authz.rego
```

### 3. Docker デーモン設定への追加

`/etc/docker/daemon.json` に authorization-plugins を追加（`--alias` で付けた名前を使用）:

```json
{
    "authorization-plugins": ["opa-docker-authz"]
}
```

Docker デーモンを再起動:

```bash
sudo systemctl restart docker
```

### 4. safe-docker との併用時の推奨構成

パターン C（safe-docker + OPA Docker AuthZ）の場合、以下の構成を推奨する:

1. **safe-docker を Layer 1 として配置**
   - Hook モード（Claude Code 連携）または Wrapper モード（docker 置換）で設定
   - セットアップ方法は [README のセットアップ](../README.md#セットアップ) を参照

2. **OPA Docker AuthZ を Layer 2 として配置**
   - 上記の手順でプラグインをインストール・設定

3. **ポリシーの一貫性を保つ**
   - safe-docker の `config.toml` で設定したルールと同等以上のルールを `authz.rego` にも記述
   - OPA 側は safe-docker 側より緩くしない（OPA は最終防衛線）
   - 例: safe-docker で `blocked_capabilities` に追加した capability は、OPA の deny ルールにも追加する

4. **監査ログの活用**
   - safe-docker の監査ログ（`config.toml` の `[audit]` セクション）を有効化
   - OPA の決定ログと合わせて分析することで、バイパスの試みを検出可能

---

## トラブルシューティング

### Docker がロックアウトされた場合

OPA ポリシーに誤りがあると、全ての Docker 操作が拒否される可能性がある。以下の手順でリカバリする:

```bash
# 方法 1: プラグインを無効化（--alias で付けた名前を使用）
docker plugin disable opa-docker-authz

# 方法 2: daemon.json から authorization-plugins を削除して Docker 再起動
sudo vi /etc/docker/daemon.json  # authorization-plugins の行を削除
sudo systemctl restart docker
```

> ポリシーで `Plugin.Disable` と `Plugin.Enable` を常に許可するルールを含めておくことで、方法 1 が確実に機能する。本リポジトリの `opa/authz.rego` にはこのルールが含まれている。

### safe-docker と OPA で判定が異なる場合

safe-docker が allow したが OPA が deny した場合:
- OPA のポリシーが safe-docker より厳しい設定になっている（これは正常な多層防御の動作）
- 必要に応じて OPA のポリシーを調整する

safe-docker が deny したが OPA が allow した場合:
- OPA のポリシーに対応するルールが不足している
- safe-docker の `config.toml` の変更に合わせて `authz.rego` も更新する

---

## safe-docker と OPA のポリシー差異

safe-docker と OPA Docker AuthZ は動作レイヤーが異なるため、それぞれが得意とする検査と、原理的に実現できない検査がある。

### safe-docker にしかできないこと

| 機能 | 理由 |
|------|------|
| **Compose ファイルの事前解析** | `docker compose up` の実行前に YAML を読み、`privileged: true` や危険な `volumes`、`env_file`、`include` を検出する。OPA が見るのは Compose が展開した後の個別コンテナ作成 API であり、Compose ファイル単位の検査はできない |
| **ask（対話的確認）** | sensitive_paths へのアクセスやイメージホワイトリスト外の使用など、完全にブロックはしないが確認を求める中間判定。OPA は allow/deny の二値のみ |
| **教育的フィードバック（Tip メッセージ）** | 「なぜ危険か」「どう設定すれば許可できるか」をユーザーやエージェントに伝える。OPA は API エラーメッセージを返せるが、情報量は限定的 |
| **シェルコマンド構文の解析**（Hook モード） | パイプ、チェイン、`eval`、`bash -c` などの間接実行を検出・展開し、その中の docker コマンドを検査する。OPA は Docker API のみを見る |
| **`--build-arg` の機密パターン検出** | `SECRET`、`PASSWORD` などの名前パターンから機密情報のリスクを推定する。OPA でも `input.Body` を検査すれば技術的には可能だが、パターンマッチの記述が煩雑になる |
| **`--env-file` / `--label-file` のパス検証** | docker がファイルを読む前に、ファイルパスが `$HOME` 外でないかを検証する。OPA が見る時点ではファイルは既に読まれ、内容が環境変数として展開済み |
| **Compose `env_file` / `include` のパス検証** | Compose が外部ファイルを参照する前にパスを検証する。OPA からは見えない |

### OPA にしかできないこと

| 機能 | 理由 |
|------|------|
| **全 API 経路の強制** | curl、SDK、スクリプト内の docker コマンドなど、CLI 以外の経路も含め全てを検査 |
| **バインドマウントのシンボリックリンク自動解決** | `opa-docker-authz` プラグインは `input.BindMounts[_].Resolved` にシンボリックリンク解決済みパスを提供。safe-docker も `canonicalize()` で解決するが、OPA 側はデーモンレベルで確実 |
| **ユーザー/グループベースのポリシー** | API リクエストの送信者情報に基づく判定が可能 |
| **レスポンスフィルタリング** | `AuthZRes` フェーズで API レスポンスを検査・フィルタできる（例: `docker inspect` の出力制限） |
| **リモートバンドルによるポリシー配信** | 中央管理サーバーからポリシーを配信し、複数ホストを一元管理 |

### 両方で実現可能なこと（ただし検査方法が異なる）

| ポリシー | safe-docker の検査対象 | OPA の検査対象 |
|----------|----------------------|---------------|
| `--privileged` ブロック | CLI 引数 `--privileged` | `HostConfig.Privileged == true` |
| バインドマウントのパス制限 | `-v /path:/dest` の `/path` 部分 | `BindMounts[_].Resolved` |
| capability ブロック | `--cap-add CAP_NAME` | `HostConfig.CapAdd[_]` |
| 名前空間フラグ | `--pid=host` 等の CLI 引数 | `HostConfig.PidMode` 等の API フィールド |
| デバイスアクセス | `--device /dev/xxx` | `HostConfig.Devices[_]` |
| security-opt | `--security-opt key=value` | `HostConfig.SecurityOpt[_]` |
| Docker ソケットマウント | `-v /var/run/docker.sock:...` | `BindMounts[_].Resolved` |
| `--sysctl` | CLI 引数 `--sysctl key=value` | `HostConfig.Sysctls` |

### まとめ

safe-docker のポリシーの**大部分**は OPA でも定義可能だが、以下の点で完全な等価にはならない:

1. **ask レベルの判定**は OPA では再現できない（allow/deny の二値のみ）
2. **Compose ファイルの事前解析**と**ホストファイルパスの事前検証**は OPA の検査範囲外
3. **シェル構文の解析**（Hook モード固有）は OPA の対象外

逆に、safe-docker だけでは **API 直接呼び出しやスクリプト経由のバイパス**を防げない。このため、両方を併用する多層防御が推奨される。

---

## ポリシーの一貫性検証

パターン C（safe-docker + OPA 併用）では、2つのレイヤーのポリシーが一貫していることが重要になる。safe-docker が deny するものを OPA が allow してしまうと、バイパス経路が生まれる。

### 自動検証: 一貫性テスト（推奨）

本リポジトリには `tests/opa_consistency_test.rs` として、safe-docker のデフォルトポリシーと `opa/authz.rego` の一貫性を検証するテストが含まれている。`cargo test` で自動実行される。

```bash
# 一貫性テストの実行
cargo test opa_consistency
```

このテストは以下を検証する:

- `default_blocked_capabilities()` の全 capability が `authz.rego` の CapAdd deny ルールに含まれているか
- `--privileged` の deny ルールが存在するか
- 全ての名前空間フラグ（PidMode, NetworkMode, IpcMode, UTSMode, CgroupnsMode, UsernsMode）の deny ルールが存在するか
- デバイスアクセスの deny ルールが存在するか
- 全ての危険な security-opt パターンの deny ルールが存在するか
- Docker ソケットマウントの deny ルールが存在するか
- バインドマウントのパス制限とパストラバーサル防止が存在するか
- プラグインのロックアウト防止ルールが存在するか
- 開発環境固有のパスがハードコードされていないか

safe-docker のポリシーを拡張した場合は、`opa/authz.rego` とこのテストも合わせて更新すること。

### 手動検証: チェックリスト方式

`config.toml` と `authz.rego` を対照しながら、以下を確認する:

```
□ blocked_flags の各フラグに対応する deny ルールが authz.rego にある
□ blocked_capabilities の各 capability が authz.rego の CapAdd チェックに含まれている
□ allowed_paths 以外のパスが authz.rego のバインドマウントチェックで拒否される
□ Docker ソケットマウントが authz.rego で拒否される
□ --pid=host, --network=host 等の名前空間フラグが authz.rego で拒否される
```

### 自動検証: --dry-run と opa eval の突き合わせ

テスト対象の docker コマンドリストを用意し、safe-docker と OPA の両方で判定を比較する:

```bash
#!/bin/bash
# consistency_check.sh - ポリシー一貫性の自動検証スクリプト例

COMMANDS=(
    "run --privileged ubuntu"
    "run -v /etc:/data ubuntu"
    "run --cap-add SYS_ADMIN ubuntu"
    "run --pid=host ubuntu"
    "run --network=host ubuntu"
    "run -v /var/run/docker.sock:/var/run/docker.sock ubuntu"
    "run -v \$HOME/projects:/app ubuntu"
    "run ubuntu echo hello"
)

echo "=== Policy Consistency Check ==="
for cmd in "${COMMANDS[@]}"; do
    # safe-docker の判定
    sd_result=$(safe-docker --dry-run $cmd 2>&1)
    sd_decision=$(echo "$sd_result" | grep -oP 'Decision: \K\w+')

    # OPA の判定 (Docker API 相当の入力を opa eval で評価)
    # 注意: Docker CLI 引数から API JSON への変換は手動で用意が必要
    # opa_result=$(opa eval -d authz.rego -i "input_${cmd_id}.json" "data.docker.authz.allow")

    echo "[$sd_decision] docker $cmd"
done
```

> **注意**: CLI 引数から Docker API の JSON 入力への変換は自明ではない。テスト用の入力 JSON を手動で用意するか、実際に docker コマンドを実行して OPA の決定ログを確認する方式が現実的。

### 実環境での継続的検証

本番環境では、safe-docker と OPA の監査ログを突き合わせることで一貫性を継続的に確認できる:

1. **safe-docker の監査ログ**（JSONL）と **OPA の決定ログ** を同一のログ基盤に集約
2. safe-docker が deny したコマンドが、OPA 側でも deny されていることを確認
3. OPA が deny したが safe-docker のログにない操作は、CLI 外のバイパス経路による操作（期待通りの動作）

```
# 不整合の検出パターン
safe-docker: deny  +  OPA: allow  → ⚠ OPA のポリシーに漏れ（要修正）
safe-docker: allow +  OPA: deny  → ℹ OPA がより厳しい（正常な多層防御）
safe-docker: deny  +  OPA: deny  → ✓ 一貫している
safe-docker: (ログなし) + OPA: deny → ℹ CLI 外の経路が OPA でブロックされた
```

---

## 参考リンク

- [opa-docker-authz (GitHub)](https://github.com/open-policy-agent/opa-docker-authz)
- [Docker Authorization Plugin API](https://docs.docker.com/engine/extend/plugins_authorization/)
- [OPA (Open Policy Agent)](https://www.openpolicyagent.org/)
- [Rego ポリシー言語](https://www.openpolicyagent.org/docs/latest/policy-language/)
- [safe-docker セキュリティモデル](../README.md#セキュリティモデル)
- [safe-docker 攻撃面分析](ATTACK_SURFACE_ANALYSIS.md)
- [safe-docker 類似プロジェクト比較分析](COMPARATIVE_ANALYSIS.md)
