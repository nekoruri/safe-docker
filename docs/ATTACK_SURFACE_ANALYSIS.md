# 攻撃面分析レポート

> safe-docker の検出カバレッジを、学術論文・CVE データベース・セキュリティガイドラインと突合したギャップ分析（v0.5.0 で初版作成、v0.8.0 時点で最終更新）。

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
| A. 権限昇格 / コンテナエスケープ | 14 | 12 | 0 | 2 |
| B. ホストファイルシステムアクセス | 5 | 5 | 0 | 0 |
| C. ネットワーク攻撃 | 4 | 4 | 0 | 0 |
| D. 情報漏洩 | 3 | 3 | 0 | 0 |
| E. リソース悪用 / DoS | 4 | 0 | 0 | 4 |
| F. ビルド時攻撃 | 3 | 2 | 1 | 0 |
| G. サプライチェーン | 3 | 0 | 2 | 1 |
| **合計** | **36** | **26** | **3** | **7** |

**残存する未検出ベクトル**: リソース悪用 / DoS（4件、低優先度）、ランタイム脆弱性（スコープ外）
**CLI 引数レベルで検出可能な未対応ベクトル**: 3件（低優先度）

---

## 2. 検出済みの攻撃ベクトル

| ID | 攻撃ベクトル | 検出フラグ | 判定 | 対応版 |
|----|-------------|-----------|------|--------|
| A1 | `--privileged` による完全ホストアクセス | `DangerousFlag::Privileged` | deny | v0.1.0 |
| A2 | `--cap-add SYS_ADMIN` 等の危険 capability | `DangerousFlag::CapAdd` | deny | v0.1.0 |
| A2+ | `--cap-add DAC_READ_SEARCH/NET_ADMIN/BPF/PERFMON/SYS_BOOT` | `blocked_capabilities` 拡充 | deny | v0.5.0 |
| A3 | `--security-opt apparmor/seccomp=unconfined` 等 | `DangerousFlag::SecurityOpt` | deny | v0.2.0 |
| A3+ | `--security-opt label=disable` (CIS 5.2) | `is_dangerous_security_opt` | deny | v0.5.0 |
| A4 | `--pid=host` ホストプロセス名前空間 | `DangerousFlag::PidHost` | deny | v0.2.0 |
| A5 | `--userns=host` ホストユーザー名前空間 | `DangerousFlag::UsernsHost` | deny | v0.2.0 |
| A6 | `--cgroupns=host` ホスト cgroup 名前空間 | `DangerousFlag::CgroupnsHost` | deny | v0.2.0 |
| A7 | `--device=/dev/xxx` ホストデバイスアクセス | `DangerousFlag::Device` | deny | v0.1.0 |
| A8 | `--uts=host` ホスト UTS 名前空間 (CIS 5.11) | `DangerousFlag::UtsHost` | deny | v0.5.0 |
| A9 | `--sysctl kernel.*` カーネルパラメータ操作 | `DangerousFlag::Sysctl` | deny | v0.5.0 |
| A13 | `--network/pid/ipc=container:NAME` コンテナ間共有 | `NetworkContainer/PidContainer/IpcContainer` | deny | v0.4.0 |
| A14 | `bind-propagation=shared/rshared` マウント伝搬 | `DangerousFlag::MountPropagation` | deny | v0.4.0 |
| B1 | バインドマウントで `$HOME` 外パス | パス検証 | deny | v0.1.0 |
| B2 | Docker ソケットマウント | パス検証 + 特別判定 | deny | v0.1.0 |
| B3 | `--volumes-from` 間接マウント継承 | `DangerousFlag::VolumesFrom` | ask | v0.2.0 |
| B4 | `--env-file` / `--label-file` によるホストファイル読み取り | `host_paths` パス検証 | deny | v0.5.0 |
| B5 | `--security-opt seccomp=PATH` ホストファイル参照 | `host_paths` パス検証 | deny | v0.5.0 |
| C1 | `--network=host` ホストネットワーク名前空間 | `DangerousFlag::NetworkHost` | deny | v0.1.0 |
| C2 | `--ipc=host` ホスト IPC 名前空間 | `DangerousFlag::IpcHost` | deny | v0.2.0 |
| C3 | `--sysctl net.*` ネットワーク設定変更 | `DangerousFlag::Sysctl` | ask | v0.5.0 |
| C4 | `--add-host` メタデータ IP (169.254.169.254) | `DangerousFlag::AddHost` | ask | v0.5.0 |
| D1 | 機密パスのマウント（`.ssh`, `.aws` 等） | sensitive_paths | ask | v0.1.0 |
| D2 | `--build-arg` に機密情報パターン | `DangerousFlag::BuildArgSecret` | ask | v0.5.0 |
| F1 | BuildKit `--secret`/`--ssh` ソースパス | `host_paths` パス検証 | deny | v0.5.0 |
| F2 | Compose `include:` 外部ファイル参照 | `host_paths` パス検証 | ask | v0.5.0 |
| F3 | Compose `env_file:` ホストファイル参照 | `env_file_paths` パス検証 | deny | v0.5.0 |

---

## 3. 検出ギャップ: CLI 引数レベルで対応可能

### 3.1 対応済み（v0.5.0 で解決）

以下は Phase 5a〜5e で対応が完了したギャップ:

| ID | ギャップ | 対応 Phase | 対応内容 |
|----|---------|-----------|---------|
| G1 | `--uts=host` | 5a | `DangerousFlag::UtsHost` 追加、Compose `uts: host` 対応 |
| G2 | blocked_capabilities 不足 | 5c | `DAC_READ_SEARCH`, `NET_ADMIN`, `BPF`, `PERFMON`, `SYS_BOOT` 追加 |
| G3 | `--env-file` パス未検証 | 5b | `host_paths` に追加、`is_flag_with_value()` 登録 |
| G4 | `--label-file` パス未検証 | 5b | 同上 |
| G5 | `seccomp=PATH` パス未検証 | 5b | `unconfined` 以外のパスを `host_paths` に追加 |
| G6 | `--sysctl` 危険値 | 5d | `kernel.*` → deny, `net.*` → ask |
| G7 | `--build-arg` 機密情報 | 5e | `BuildArgSecret` パターン検出 → ask |
| G8 | Compose `uts`, `sysctls`, `env_file` | 5a/5d/5b | 各ディレクティブの検出を追加 |
| G9 | `--add-host` メタデータ IP | 5d | `169.254.169.254`, `fd00:ec2::254` → ask |
| - | `is_flag_with_value()` 欠損 | 5a | 25+ フラグ追加（パース正確性向上） |
| - | `--security-opt label=disable` | 5d | CIS 5.2 準拠、deny |
| - | BuildKit `--secret`/`--ssh` パス | 5e | ソースパスの $HOME 外 → deny |
| - | Compose `include:` | 5e | 参照先パスの $HOME 外 → ask |

### 3.2 残存ギャップ（低優先度）

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

## 5. `is_flag_with_value()` の欠損フラグ — ✅ 対応済み (Phase 5a)

Phase 5a で 25+ フラグが追加され、セキュリティ上重要なもの（`--env-file`, `--label-file`, `--uts`, `--pid` 等）および
パース正確性に影響するもの（`--device-*`, `--cpu-*`, `--memory-*`, `--pids-limit` 等）がすべて登録済み。

---

## 6. 対応優先度マトリクス — ✅ Phase 5 で完了

Phase 5a〜5e で高優先度・中優先度のギャップがすべて解決済み。

残存する低優先度の項目:
- **G10**: `-e PASSWORD=xxx` パターン検出（false positive リスクが高い）
- **G11**: リソース制限不在検出（開発環境では低リスク）

---

## 7. CIS Docker Benchmark との対応表

CIS Benchmark のコンテナランタイム設定（セクション 5）との対応:

| CIS # | 推奨事項 | safe-docker | 状態 |
|--------|---------|------------|------|
| 5.1 | AppArmor プロファイルの適用 | `--security-opt apparmor=unconfined` を deny | **対応済み** |
| 5.2 | SELinux プロファイルの適用 | `--security-opt label=disable` / `label:disable` を deny | **対応済み (v0.5.0)** |
| 5.3 | Linux capability の制限 | `blocked_capabilities` で 10 種の capability をブロック | **対応済み (v0.5.0 で拡充)** |
| 5.4 | --privileged 禁止 | deny | **対応済み** |
| 5.7 | ホストデバイスマウント禁止 | `--device` deny | **対応済み** |
| 5.9 | --network=host 禁止 | deny | **対応済み** |
| 5.11 | --uts=host 禁止 | deny | **対応済み (v0.5.0)** |
| 5.12 | --pid=host 禁止 | deny | **対応済み** |
| 5.14 | seccomp プロファイルの適用 | `seccomp=unconfined` を deny + パス検証 | **対応済み (v0.5.0 でパス検証追加)** |
| 5.15 | --userns=host 禁止 | deny | **対応済み** |
| 5.16 | Docker ソケットマウント禁止 | deny | **対応済み** |
| 5.17 | --cgroupns=host 禁止 | deny | **対応済み** |
| 5.28 | --pids-limit の設定 | **未対応** | ギャップ（低優先度） |
| 5.31 | --ipc=host 禁止 | deny | **対応済み** |

---

## 8. 対応履歴

Phase 5a〜5e（v0.5.0）で以下のギャップをすべて解決:

- **5a**: `is_flag_with_value()` 25+ フラグ補完 + `--uts=host` 検出 + Compose `uts: host`
- **5b**: `--env-file`/`--label-file` パス検証 + `seccomp=PROFILE` パス検証 + Compose `env_file:` パス検証
- **5c**: `blocked_capabilities` 拡充（`DAC_READ_SEARCH`, `NET_ADMIN`, `BPF`, `PERFMON`, `SYS_BOOT`）
- **5d**: `--sysctl` 危険値検出 + `--add-host` メタデータ IP + Compose `sysctls:` + CIS 5.2 `label=disable`
- **5e**: `--build-arg` 機密パターン + BuildKit `--secret`/`--ssh` パス検証 + Compose `include:` パス検証
