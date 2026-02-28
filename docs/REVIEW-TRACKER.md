# Review Comment Tracker

今週 (2026-02-25〜02-28) マージされた PR に対するレビューコメントの追跡。
レビュアーはすべて bot (GitHub Copilot / ChatGPT Codex)。

## ステータス凡例

- 🔴 **未対応** — 対応が必要
- 🟡 **対応中** — 作業中
- 🟢 **対応済み** — 修正完了
- ⚪ **見送り** — 意図的に対応しない（理由付き）
- 🔵 **PR#32で対応済み** — 既に別PRで修正済み

---

## セキュリティ関連 (優先度: 高)

### SEC-01: メタデータ IP の IPv6 バイパス [PR #17, Codex P1]
- **ファイル**: `src/policy.rs:129`
- **内容**: `--add-host` のメタデータ IP チェックが完全一致のため、IPv6 の大文字表記 (`FD00:EC2::254`) や展開表記でバイパス可能。アドレスのパース/正規化が必要。
- **ステータス**: 🟢 対応済み (is_metadata_endpoint ヘルパーで IPv6 正規化)

### SEC-02: メタデータ IP チェックがブラケット形式・ドメイン名を検出しない [PR #17, Copilot]
- **ファイル**: `src/policy.rs:134`
- **内容**: `.contains()` ベースのため `[fd00:ec2::254]`（ブラケット形式）や `metadata.google.internal` 等のドメイン名を検出しない。
- **ステータス**: 🟢 対応済み (is_metadata_endpoint でブラケット除去・ドメイン名チェック)

### SEC-03: Compose `extra_hosts` でメタデータ IP 未検出 [PR #17, Copilot]
- **ファイル**: `src/compose.rs:225`
- **内容**: CLI の `--add-host` では検出するが、Compose の `extra_hosts` フィールドで同等の検出がない。suggestion コード付き。
- **ステータス**: 🟢 対応済み (extra_hosts パース + AddHost match アーム追加)

### SEC-04: Compose 側で `MountPropagation` が未処理 [PR #14, Copilot]
- **ファイル**: `src/policy.rs:202`
- **内容**: CLI 側 (L101-106) では対応済みだが、Compose 側の match に `DangerousFlag::MountPropagation` のケースがない。suggestion コード付き。
- **ステータス**: 🟢 対応済み (MountPropagation + AddHost + BuildArgSecret アーム追加)

### SEC-05: `is_secret_build_arg` が `KEY` トークンを未検出 [PR #18, Codex P2]
- **ファイル**: `src/docker_args.rs:240`
- **内容**: `AWS_ACCESS_KEY` や `SERVICE_KEY` 等の `KEY` パターンが検出されず、Ask フローをスキップする。
- **ステータス**: 🟢 対応済み (_KEY suffix, _KEY_ infix, KEY exact match 追加)

### SEC-06: IPv6 メタデータの統合テスト欠落 [PR #17, Copilot]
- **ファイル**: `tests/security_test.rs:781`
- **内容**: ユニットテストはあるが、IPv6 メタデータエンドポイント (`fd00:ec2::254`) のE2Eテストがない。
- **ステータス**: 🟢 対応済み (IPv6, 大文字, ブラケット, ドメイン名の E2E テスト追加)

---

## 重要な不具合 (優先度: 高)

### BUG-01: `--target` パースが後続フラグを値として誤認 [PR #30 Codex, PR #32 Copilot]
- **ファイル**: `src/setup.rs`
- **内容**: `safe-docker setup --target --force` で `--force` がディレクトリパスとして扱われる。`-` で始まる値を拒否すべき。
- **ステータス**: 🔵 PR#32 で対応済み

### BUG-02: `--target` に値がない場合のバリデーション不足 [PR #30, Codex P2]
- **ファイル**: `src/setup.rs:134`
- **内容**: `safe-docker setup --target`（DIR なし）がエラーにならず、デフォルトパスにシンボリックリンクを作成してしまう。
- **ステータス**: 🔵 PR#32 で対応済み

### BUG-03: `PathBuf::from("~")` フォールバック問題 [PR #30, Copilot]
- **ファイル**: `src/setup.rs:24`
- **内容**: `home_dir()` が None の場合にリテラル `~` パスが作られ、シェル展開されない。エラーまたは current_dir フォールバックにすべき。
- **ステータス**: 🔵 PR#32 で対応済み

### BUG-04: pre-commit スクリプトのパス内スペース脆弱性 [PR #32, Copilot]
- **ファイル**: `scripts/pre-commit`
- **内容**: `STAGED_RS_FILES` が改行区切りで xargs に渡されるが、パスにスペースがあると壊れる。NUL 区切り (`-z` + `xargs -0`) を使うべき。
- **ステータス**: 🔵 PR#32 で対応済み

### BUG-05: テスト名の誤り `test_wrapper_allow_compose_env_file_relative` [PR #19, Copilot]
- **ファイル**: `tests/wrapper_test.rs:1056`
- **内容**: テスト名が「allow」だが実際は deny を期待している。リネームが必要。
- **ステータス**: 🟢 対応済み (test_wrapper_deny_compose_env_file_relative にリネーム)

### BUG-06: `test_default_target_dir` が環境依存で flaky [PR #32, Copilot]
- **ファイル**: `src/setup.rs:471`
- **内容**: `default_target_dir()` が None を返しうるが、テストが `is_some()` を前提としている。HOME を temp dir に設定して確定的にすべき。
- **ステータス**: 🔴 未対応

### BUG-07: `print_real_docker_info` が `Config::default()` を使用 [PR #30, Codex P2]
- **ファイル**: `src/setup.rs:279`
- **内容**: ユーザーの `config.toml` で `wrapper.docker_path` を設定していても無視される。
- **ステータス**: 🔵 PR#32 で対応済み

---

## コード品質 (優先度: 中)

### QOL-01: `TempEnvVar` が任意の `Mutex<()>` ガードを受け入れる [PR #29 Codex, PR #32 Copilot]
- **ファイル**: `src/test_utils.rs`
- **内容**: `ENV_MUTEX` 以外のミューテックスのガードでも動作してしまい unsound。`MutexGuard<'static, ()>` に制限するか専用 newtype を導入すべき。
- **ステータス**: 🔵 PR#32 で MutexGuard 引数化は対応済み。追加指摘（任意 Mutex 受け入れ）は 🔴 未対応

### QOL-02: Compose `analyze_compose()` の services 二重走査 [PR #19, Copilot]
- **ファイル**: `src/compose.rs:64`
- **内容**: volumes 用と env_file 用で services マッピングを2回走査。1回のループにまとめるべき。
- **ステータス**: 🔴 未対応

### QOL-03: `extract_service_env_file_paths` の引数名 `host_paths` が紛らわしい [PR #19, Copilot]
- **ファイル**: `src/compose.rs:252`
- **内容**: `analysis.host_paths`（include 用）と混同しやすい。`env_file_paths` にリネームすべき。
- **ステータス**: 🔴 未対応

### QOL-04: `build_event` の引数が多すぎる [PR #22, Copilot]
- **ファイル**: `src/audit.rs:83`
- **内容**: コンテキスト構造体にリファクタリングすべき。
- **ステータス**: 🔴 未対応

### QOL-05: `config_source` 文字列のモード間不統一 [PR #22, Copilot]
- **ファイル**: `src/main.rs:245`
- **内容**: Hook モードは `"(default)"`、Wrapper モードは `"(default - no config file)"` 等、異なるフォーマット。
- **ステータス**: 🔴 未対応

### QOL-06: `config_source` フィールドのドキュメントコメントが不完全 [PR #22, Copilot]
- **ファイル**: `src/audit.rs:31`
- **内容**: `"(default)"` のみ記載だが、実際は `"... (FAILED, using defaults)"` 等もある。suggestion 付き。
- **ステータス**: 🔴 未対応

### QOL-07: pre-commit スクリプトのコメントと実装の不一致 [PR #32, Copilot]
- **ファイル**: `scripts/pre-commit:11`
- **内容**: ヘッダが `cargo fmt --check` だが実際は rustfmt を直接実行。
- **ステータス**: 🔴 未対応

### QOL-08: Compose sysctl の float/boolean/null 値型未対応 [PR #17, Copilot]
- **ファイル**: `src/compose.rs:219`
- **内容**: sysctl マッピングで i64/string 以外の型が空文字になる。suggestion 付き。
- **ステータス**: 🔴 未対応

### QOL-09: wrapper.rs の sysctl tip メッセージが不正確 [PR #17, Copilot]
- **ファイル**: `src/wrapper.rs:357`
- **内容**: 「net.* は使える」と書いているが実際は ask (確認必要)。
- **ステータス**: 🔴 未対応

### QOL-10: Compose 空コンテナ名バリデーション [PR #14, Copilot]
- **ファイル**: `src/compose.rs:131`, `src/docker_args.rs:409`
- **内容**: `container:` や `service:` の後に空文字を許容。Docker 自体が拒否するが、エラーメッセージ改善のため検証すべき。
- **ステータス**: 🔴 未対応

### QOL-11: slave/rslave propagation の安全性テスト追加 [PR #14, Copilot]
- **ファイル**: `src/docker_args.rs:1330`
- **内容**: shared/rshared のみ danger だが、slave/rslave が安全であることを明示するテストがない。
- **ステータス**: 🔴 未対応

### QOL-12: Compose IPC container namespace テスト欠落 [PR #14, Copilot]
- **ファイル**: `tests/security_test.rs:539`
- **内容**: network_mode と pid にはテストがあるが ipc がない。service: プレフィックスのテストも欠落。suggestion コード付き。
- **ステータス**: 🟢 対応済み (ipc: container:, ipc: service: テスト追加)

---

## ドキュメント (優先度: 低)

### DOC-01: OPA ガイドのポリシーファイルパス不整合 [PR #27, Copilot]
- **ファイル**: `docs/OPA_DOCKER_AUTHZ.md:308`
- **内容**: `opa-args` が `/opa/authz.rego` を参照するが、次の手順では `/etc/docker/config/authz.rego` にコピー。
- **ステータス**: 🟢 対応済み (OPA ガイドはプラグイン rootfs へのコピーで一貫。README の OPA セクションの誤ったパス参照を修正)

### DOC-02: OPA ガイドのプラグイン名不一致 [PR #27, Copilot]
- **ファイル**: `docs/OPA_DOCKER_AUTHZ.md:340`
- **内容**: `authorization-plugins` と README の `docker plugin disable` でプラグイン名が異なる。
- **ステータス**: 🟢 対応済み (現在は `opa-docker-authz` で統一済み)

### DOC-03: OPA ガイドのホームディレクトリパス不整合 [PR #27, Copilot]
- **ファイル**: `docs/OPA_DOCKER_AUTHZ.md`
- **内容**: ガイドは `/home/username/` だが、`opa/authz.rego` は `/home/masa/` がハードコード。
- **ステータス**: 🟢 対応済み (`opa/authz.rego` は `/home/username/` に修正済み。一貫性テストでもハードコードパスを検出)

### DOC-04: OPA ガイドの capability deny 例と実装の不整合 [PR #27, Copilot]
- **ファイル**: `docs/OPA_DOCKER_AUTHZ.md`
- **内容**: `opa/authz.rego` の実装範囲と本文の説明が不一致。
- **ステータス**: 🟢 対応済み (rego の capability リストは safe-docker の default_blocked_capabilities() と一致。一貫性テストで自動検証)

### DOC-05: OPA ガイドのポリシー対応表に未実装項目 [PR #27, Copilot]
- **ファイル**: `docs/OPA_DOCKER_AUTHZ.md:287`
- **内容**: `HostConfig.Devices` 等は deny ルールがないが、表に含まれている。
- **ステータス**: 🟢 対応済み (rego に Devices の deny ルール存在。対応表の全項目に対応する deny ルールが実装済み)

### DOC-06: ATTACK_SURFACE_ANALYSIS で `--uts=host` が未対応のまま [PR #16, Copilot]
- **ファイル**: `docs/ATTACK_SURFACE_ANALYSIS.md:237`
- **内容**: PR#16 で実装済みだが、ステータスが「未対応/ギャップ」のまま。suggestion 付き。
- **ステータス**: 🟢 対応済み (A8 として検出済みに記載、G1 として対応済みギャップに記載)

### DOC-07: ATTACK_SURFACE_ANALYSIS のバージョン表記が不整合 [PR #19, Copilot]
- **ファイル**: `docs/ATTACK_SURFACE_ANALYSIS.md:3`
- **内容**: 「v0.5.0」と記載だが当時の Cargo.toml は 0.4.0。
- **ステータス**: 🟢 対応済み (初版作成バージョンと最終更新バージョンを明記する形式に修正)

### DOC-08: README インストール手順のグロブ安全性 [PR #13, Copilot]
- **ファイル**: `README.md:149`
- **内容**: グロブで複数ファイルがマッチする場合に誤ったアーティファクトを検証/展開する可能性。
- **ステータス**: 🟢 対応済み (専用ディレクトリにダウンロードし、変数で展開対象を特定する手順に修正)

### DOC-09: SUPPLY_CHAIN_SECURITY のコミットハッシュ記述 [PR #13, Copilot]
- **ファイル**: `docs/SUPPLY_CHAIN_SECURITY.md:211`
- **内容**: 「commit ハッシュがソースの完全性を保証」は不正確。署名済みタグの検証を推奨する表現に修正すべき。
- **ステータス**: 🟢 対応済み (署名済みタグの検証を推奨する表現に修正)

---

## CI/ビルド (優先度: 低)

### CI-01: release.yml の権限スコーピング [PR #13, Copilot]
- **ファイル**: `.github/workflows/release.yml:11`
- **内容**: ワークフローレベルで `contents: write` を全ジョブに付与。ジョブごとにスコープすべき。
- **ステータス**: 🔴 未対応

### CI-02: sha256sum のグロブ順序が非決定的 [PR #13, Copilot]
- **ファイル**: `.github/workflows/release.yml:94`
- **内容**: `LC_ALL=C` と `sort` で安定化すべき。suggestion 付き。
- **ステータス**: 🔴 未対応

### CI-03: macOS CI で両アーキテクチャ未検証 [PR #24, Codex/Copilot]
- **ファイル**: `.github/workflows/ci.yml`, `docs/ROADMAP.md`
- **内容**: `macos-latest` 1ジョブのみで Intel/Apple Silicon 両方は未検証。ROADMAP の文言調整が必要。
- **ステータス**: ⚪ 見送り (意図的に macos-latest のみに戻す判断済み。ROADMAP 文言は要更新)

### CI-04: pre-commit の実行権限ドキュメント不足 [PR #28, Copilot]
- **ファイル**: `docs/CONTRIBUTING.md:10`
- **内容**: `chmod +x scripts/pre-commit` の手順が欠けている。
- **ステータス**: 🔴 未対応

---

## 見送り済み

### SKIP-01: `--build-arg` 等が次フラグを値として誤消費 [PR #18, Copilot]
- **内容**: コードベース全体の問題であり、この PR をブロックすべきではない。broader refactoring で対応。
- **ステータス**: ⚪ 見送り (将来のリファクタリングで対応)

### SKIP-02: PR #26 の PR 説明と diff の不一致 [PR #26, Copilot]
- **内容**: リリース PR の性質上、変更は他 PR で既にマージ済み。
- **ステータス**: ⚪ 見送り (実害なし)
