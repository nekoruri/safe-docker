# 攻撃面分析レポート

> v0.4.0 時点の safe-docker の検出カバレッジを、学術論文・CVE データベース・セキュリティガイドラインと突合したギャップ分析。

## 調査ソース

- NIST SP 800-190 (Application Container Security Guide)
- CIS Docker Benchmark
- OWASP Docker Security Cheat Sheet / Docker Top 10
- HackTricks Docker Breakout / Privilege Escalation
- Unit 42 (Palo Alto Networks) Container Escape Techniques
- Snyk Leaky Vessels 分析
- Trail of Bits コンテナセキュリティ研究
- Datadog Container Security Fundamentals
- Cybereason Capability-based Escape 研究
- 各 CVE アドバイザリ (2022-2025)

---

## 1. カバレッジサマリー

| カテゴリ | 攻撃ベクトル数 | 検出済み | 部分的 | 未検出 |
|----------|---------------|---------|--------|--------|
| A. 権限昇格 / コンテナエスケープ | 14 | 8 | 2 | 4 |
| B. ホストファイルシステムアクセス | 5 | 3 | 1 | 1 |
| C. ネットワーク攻撃 | 4 | 2 | 0 | 2 |
| D. 情報漏洩 | 3 | 2 | 0 | 1 |
| E. リソース悪用 / DoS | 4 | 0 | 0 | 4 |
| F. ビルド時攻撃 | 3 | 0 | 1 | 2 |
| G. サプライチェーン | 3 | 0 | 2 | 1 |
| **合計** | **36** | **15** | **6** | **15** |

**CLI 引数レベルで検出可能な未対応ベクトル**: 8件（対応推奨）
**ランタイム脆弱性でスコープ外**: 7件（文書化のみ）

---

## 2. 検出済みの攻撃ベクトル（v0.4.0）

| ID | 攻撃ベクトル | 検出フラグ | 判定 |
|----|-------------|-----------|------|
| A1 | `--privileged` による完全ホストアクセス | `DangerousFlag::Privileged` | deny |
| A2 | `--cap-add SYS_ADMIN` 等の危険 capability | `DangerousFlag::CapAdd` | deny |
| A3 | `--security-opt apparmor/seccomp=unconfined` 等 | `DangerousFlag::SecurityOpt` | deny |
| A4 | `--pid=host` ホストプロセス名前空間 | `DangerousFlag::PidHost` | deny |
| A5 | `--userns=host` ホストユーザー名前空間 | `DangerousFlag::UsernsHost` | deny |
| A6 | `--cgroupns=host` ホスト cgroup 名前空間 | `DangerousFlag::CgroupnsHost` | deny |
| A7 | `--device=/dev/xxx` ホストデバイスアクセス | `DangerousFlag::Device` | deny |
| A13 | `--network/pid/ipc=container:NAME` コンテナ間共有 | `NetworkContainer/PidContainer/IpcContainer` | deny |
| A14 | `bind-propagation=shared/rshared` マウント伝搬 | `DangerousFlag::MountPropagation` | deny |
| B1 | バインドマウントで `$HOME` 外パス | パス検証 | deny |
| B2 | Docker ソケットマウント | パス検証 + 特別判定 | deny |
| B3 | `--volumes-from` 間接マウント継承 | `DangerousFlag::VolumesFrom` | ask |
| C1 | `--network=host` ホストネットワーク名前空間 | `DangerousFlag::NetworkHost` | deny |
| C2 | `--ipc=host` ホスト IPC 名前空間 | `DangerousFlag::IpcHost` | deny |
| D1 | 機密パスのマウント（`.ssh`, `.aws` 等） | sensitive_paths | ask |

---

## 3. 検出ギャップ: CLI 引数レベルで対応可能

以下はコマンドライン引数を検査することで検出可能だが、現在未対応のもの。

### 3.1 高優先度

#### G1: `--uts=host` — UTS 名前空間の共有

- **リスク**: ホスト名の変更が可能。ネットワーク認証やサービス発見の操作に悪用可能
- **CIS Docker Benchmark**: 5.11 で禁止を推奨
- **対応方法**: `DangerousFlag::UtsHost` を追加、`--uts=host` / `--uts host` をパース
- **注意**: `--uts` は `is_flag_with_value()` に未登録。追加が必要

#### G2: blocked_capabilities の拡充

- **現在**: `SYS_ADMIN`, `SYS_PTRACE`, `SYS_MODULE`, `SYS_RAWIO`, `ALL`
- **推奨追加**: Docker がデフォルトで付与しない capability のうち、コンテナエスケープに利用可能なもの:

| Capability | リスク | 推奨 |
|-----------|--------|------|
| `DAC_READ_SEARCH` | 全ファイル読み取り権限バイパス。`open_by_handle_at(2)` によるファイルシステム直接アクセス | **追加** |
| `NET_ADMIN` | iptables 操作、ARP スプーフィング、promiscuous モード、ネットワーク完全制御 | **追加** |
| `BPF` | eBPF プログラムロード。カーネル空間でコード実行、サイドチャネル攻撃 | **追加** |
| `PERFMON` | パフォーマンスモニタリング。サイドチャネル攻撃の足掛かり | **追加** |
| `SYS_BOOT` | ホストの再起動が可能 | **追加** |

- **根拠**: Trail of Bits, Cybereason の研究で、これらの capability 単体でコンテナエスケープまたは重大な情報漏洩が可能であることが実証されている

#### G3: `--env-file` のパス検証

- **リスク**: `--env-file /etc/shadow` のように指定すると、ホスト上の任意ファイルの内容が環境変数としてコンテナに読み込まれる。情報漏洩の直接的な手段
- **現状**: `is_flag_with_value()` に `--env-file` が**含まれていない**。次の引数がイメージ名として誤認され、後続のフラグ検出が失敗する可能性がある（CLAUDE.md に記載の `is_flag_with_value()` の重要性に該当）
- **対応方法**: `--env-file` を `is_flag_with_value()` に追加し、値を `host_paths` に追加してパス検証を適用

#### G4: `--label-file` のパス検証

- **リスク**: `--env-file` と同様、ホスト上のファイルを読み取る
- **現状**: `is_flag_with_value()` に未登録
- **対応方法**: G3 と同様

#### G5: `--security-opt seccomp=PROFILE_PATH` のパス検証

- **リスク**: カスタム seccomp プロファイルのファイルパスが `$HOME` 外を参照する場合
- **現状**: `seccomp=unconfined` は deny だが、`seccomp=/etc/my-profile.json` のパスは未検証
- **対応方法**: `seccomp=` の値が `unconfined` でない場合、パスとして検証

### 3.2 中優先度

#### G6: `--sysctl` の危険な値

- **リスク**: `--sysctl net.ipv4.ip_forward=1` でコンテナをルーターにする、`kernel.core_pattern=|/path` でコアダンプ時に任意コード実行等
- **現状**: `is_flag_with_value()` に含まれているがスキップのみ
- **対応方法**: `kernel.*` プレフィックスの sysctl は deny、`net.*` の一部は ask

#### G7: `docker build --build-arg` の機密情報パターン

- **リスク**: `--build-arg AWS_SECRET_ACCESS_KEY=xxx` でビルドイメージ内に機密情報が残留
- **対応方法**: `--build-arg` の key に `SECRET`, `PASSWORD`, `TOKEN`, `KEY` 等のパターンがあれば ask

#### G8: Compose `uts`, `sysctls`, `env_file` の検出

- **リスク**: CLI で検出する項目と同じリスクが Compose ファイル経由でも発生
- **対応方法**: `compose.rs` の `extract_service_dangerous_settings()` に追加

### 3.3 低優先度（限定的リスクまたは検出困難）

#### G9: `--add-host` のメタデータサービス IP

- **リスク**: `--add-host=metadata:169.254.169.254` でクラウドメタデータへのリダイレクト
- **限定理由**: コンテナ内の `/etc/hosts` のみに影響。ローカル開発ではクラウドメタデータの問題は稀

#### G10: `-e` / `--env` の機密情報パターン

- **リスク**: `-e PASSWORD=xxx` でプロセス環境変数に秘密情報が露出
- **限定理由**: false positive が多い。Docker Secrets や `--env-file` の使用を推奨するのが適切

#### G11: リソース制限の不在検出

- **リスク**: `--pids-limit`, `--memory` 未指定でフォークボムやメモリ枯渇
- **限定理由**: 開発環境では通常問題にならない。CI/CD やプロダクション向け

---

## 4. ランタイム脆弱性（CLI 引数検査のスコープ外）

以下はランタイムやカーネルの脆弱性であり、safe-docker では検出できない。Docker Engine / runc のアップデートで対処する。

| CVE | 名称 | 説明 |
|-----|------|------|
| CVE-2024-21626 | Leaky Vessels (runc) | FD リークによる WORKDIR 悪用でコンテナエスケープ |
| CVE-2024-23651 | Leaky Vessels (BuildKit) | キャッシュマウントの race condition |
| CVE-2024-23652 | Leaky Vessels (BuildKit) | ビルド時の任意ファイル削除 |
| CVE-2024-23653 | Leaky Vessels (BuildKit) | API 経由の権限昇格 |
| CVE-2025-31133 | runc masked paths | masked path 操作で /proc に書き込み |
| CVE-2025-9074 | Docker Desktop | ソケットマウントなしで Engine API にアクセス |
| CVE-2022-0492 | cgroups release_agent | cgroup v1 でホストコード実行（`--cgroupns=host` をブロックすることで間接的に緩和済み） |
| CVE-2024-41110 | Docker AuthZ bypass | 認可プラグインの回帰バグ |
| CVE-2025-23266 | NVIDIA Container Toolkit | LD_PRELOAD 操作でコンテナエスケープ |

---

## 5. `is_flag_with_value()` の欠損フラグ

CLAUDE.md に記載の通り、このリストの不足は**後続のフラグ検出失敗**を引き起こす。以下は現在不足しているフラグ:

### セキュリティ上重要（要追加）

| フラグ | 理由 |
|--------|------|
| `--env-file` | ホストファイル読み取り。未登録だと次の引数がイメージ名と誤認される |
| `--label-file` | 同上 |
| `--uts` | UTS 名前空間。個別パース追加時に併せて登録 |
| `--pid` | 既に個別パースあり。`--pid` 単体で `is_flag_with_value` にもあると安全 |

### パース正確性向上（推奨追加）

| フラグ | 理由 |
|--------|------|
| `--device-cgroup-rule` | 値を取るフラグ |
| `--device-read-bps` | 値を取るフラグ |
| `--device-write-bps` | 値を取るフラグ |
| `--device-read-iops` | 値を取るフラグ |
| `--device-write-iops` | 値を取るフラグ |
| `--blkio-weight` | 値を取るフラグ |
| `--cpu-shares` / `-c` | 値を取るフラグ |
| `--cpuset-cpus` | 値を取るフラグ |
| `--cpuset-mems` | 値を取るフラグ |
| `--cpu-period` | 値を取るフラグ |
| `--cpu-quota` | 値を取るフラグ |
| `--memory-swap` | 値を取るフラグ |
| `--memory-swappiness` | 値を取るフラグ |
| `--memory-reservation` | 値を取るフラグ |
| `--group-add` | 値を取るフラグ |
| `--domainname` | 値を取るフラグ |
| `--oom-score-adj` | 値を取るフラグ |
| `--pids-limit` | 値を取るフラグ |
| `--isolation` | 値を取るフラグ |
| `--init` | ブーリアンだが `--init=false` 形式あり |

---

## 6. 対応優先度マトリクス

影響度（縦）× 実装コスト（横）:

```
          低コスト           中コスト           高コスト
高影響  | G1: --uts=host    | G2: capabilities |
        | G3: --env-file   | G6: --sysctl     |
        | G4: --label-file |                  |
        | G5: seccomp path |                  |
中影響  | is_flag 欠損補完  | G7: --build-arg  | G8: Compose拡張
低影響  |                  | G9: --add-host   | G10: -e パターン
        |                  |                  | G11: リソース制限
```

### 推奨実装順

1. **Phase 5a** (is_flag_with_value 補完 + --uts=host): パース正確性の根本改善
2. **Phase 5b** (--env-file/--label-file パス検証 + seccomp パス): ホストファイル読み取りの防止
3. **Phase 5c** (blocked_capabilities 拡充): capability エスケープの防止
4. **Phase 5d** (--sysctl 危険値 + Compose 対応): ネットワーク/カーネル操作の防止

---

## 7. CIS Docker Benchmark との対応表

CIS Benchmark のコンテナランタイム設定（セクション 5）との対応:

| CIS # | 推奨事項 | safe-docker | 状態 |
|--------|---------|------------|------|
| 5.1 | AppArmor プロファイルの適用 | `--security-opt apparmor=unconfined` を deny | **対応済み** |
| 5.2 | SELinux プロファイルの適用 | 未対応（`label:disable` の検出なし） | **ギャップ** |
| 5.3 | Linux capability の制限 | `blocked_capabilities` で主要なもの | **部分対応** |
| 5.4 | --privileged 禁止 | deny | **対応済み** |
| 5.7 | ホストデバイスマウント禁止 | `--device` deny | **対応済み** |
| 5.9 | --network=host 禁止 | deny | **対応済み** |
| 5.11 | --uts=host 禁止 | **未対応** | **ギャップ** |
| 5.12 | --pid=host 禁止 | deny | **対応済み** |
| 5.14 | seccomp プロファイルの適用 | `seccomp=unconfined` を deny | **対応済み** |
| 5.15 | --userns=host 禁止 | deny | **対応済み** |
| 5.16 | Docker ソケットマウント禁止 | deny | **対応済み** |
| 5.17 | --cgroupns=host 禁止 | deny | **対応済み** |
| 5.28 | --pids-limit の設定 | **未対応** | ギャップ（低優先度） |
| 5.31 | --ipc=host 禁止 | deny | **対応済み** |

---

## 8. 次のアクション

この分析に基づき、docs/ROADMAP.md の「未着手タスク」セクションを更新する。
Phase 5 として以下を追加:

- 5a: is_flag_with_value 欠損補完 + `--uts=host` 検出
- 5b: `--env-file` / `--label-file` パス検証 + `seccomp=PROFILE` パス検証
- 5c: blocked_capabilities デフォルト拡充 (`DAC_READ_SEARCH`, `NET_ADMIN`, `BPF`, `PERFMON`, `SYS_BOOT`)
- 5d: `--sysctl` 危険値検出 + Compose 対応 (`uts`, `sysctls`, `env_file`)
