# サプライチェーンセキュリティ

safe-docker のリリースバイナリは **GitHub Artifact Attestations** により署名済みのビルド証明（build provenance）が付与されています。このドキュメントでは、その背景にあるエコシステムと検証方法を説明します。

## 概要: なぜバイナリ署名が必要か

OSS のバイナリ配布には以下のリスクがある:

1. **ビルド環境の改ざん**: CI/CD パイプラインが侵害され、悪意あるコードが混入する
2. **リリースアーティファクトの差し替え**: ビルド後にバイナリが改ざんされる
3. **なりすまし**: 第三者が正規のプロジェクトを装ってバイナリを配布する

チェックサム（SHA256）は「ダウンロードしたファイルが壊れていないこと」を確認できるが、「そもそもチェックサム自体が改ざんされていないこと」は保証しない。電子署名による証明はこのギャップを埋める。

## エコシステムの全体像

safe-docker が利用するサプライチェーンセキュリティの仕組みは、以下の3層で構成される:

```
┌─────────────────────────────────────────────────────┐
│  GitHub Artifact Attestations                       │
│  (GitHub が提供するインターフェース)                 │
│  - ワークフローに 1 ステップ追加するだけで利用可能   │
│  - gh attestation verify で検証                     │
├─────────────────────────────────────────────────────┤
│  Sigstore                                           │
│  (署名・検証の基盤技術)                             │
│  - 鍵管理不要の keyless signing                     │
│  - 透明性ログによる改ざん検出                       │
├─────────────────────────────────────────────────────┤
│  SLSA (Supply-chain Levels for Software Artifacts)  │
│  (フレームワーク・成熟度モデル)                     │
│  - ビルドの信頼性をレベルで定義                     │
│  - safe-docker は Level 2 を達成                    │
└─────────────────────────────────────────────────────┘
```

## Sigstore とは

[Sigstore](https://www.sigstore.dev/) は Linux Foundation 傘下のプロジェクトで、ソフトウェアの署名と検証を無料で提供する公共インフラ。

### 従来の署名（GPG 等）の課題

- **鍵管理が困難**: 秘密鍵の安全な保管、ローテーション、失効管理が必要
- **鍵の漏洩リスク**: 秘密鍵が漏洩すると過去の署名もすべて信頼できなくなる
- **Web of Trust の破綻**: GPG の信頼モデルは一般ユーザーにとって複雑すぎる

### Sigstore の解決策: Keyless Signing

Sigstore は **短命証明書**（有効期間: 約10分）を使った keyless signing を実現する:

1. **署名者が OIDC トークンを取得**: GitHub Actions の場合、ワークフロー実行時に GitHub が自動発行する ID トークンを使用
2. **Fulcio（認証局）が短命証明書を発行**: OIDC トークンを検証し、署名者の identity（例: `https://github.com/nekoruri/safe-docker/.github/workflows/release.yml`）を含む証明書を発行
3. **成果物に署名**: 短命証明書の秘密鍵で成果物に署名
4. **Rekor（透明性ログ）に記録**: 署名の事実を改ざん不可能なログに記録
5. **秘密鍵を破棄**: 署名完了後、秘密鍵は即座に破棄される

この仕組みにより:
- **鍵管理が一切不要**: 秘密鍵は使い捨てで、保管する必要がない
- **署名者の identity が暗号的に証明される**: 「この成果物は、このワークフローで、このリポジトリからビルドされた」ことが検証可能
- **透明性ログにより改ざんが検出可能**: すべての署名イベントが公開ログに記録される

### Sigstore の構成要素

| コンポーネント | 役割 |
|--------------|------|
| **Fulcio** | 短命証明書を発行する認証局（CA） |
| **Rekor** | 署名イベントを記録する透明性ログ（Certificate Transparency と類似） |
| **cosign** | コンテナイメージやバイナリの署名・検証 CLI ツール |

## SLSA とは

[SLSA](https://slsa.dev/)（Supply-chain Levels for Software Artifacts、「サルサ」と読む）は、ソフトウェアのサプライチェーンセキュリティを段階的に評価するフレームワーク。

### SLSA Build Level

| レベル | 要件 | 意味 |
|--------|------|------|
| Level 0 | なし | 証明なし |
| Level 1 | ビルドプロセスの文書化 | provenance が存在する |
| Level 2 | ホスト型ビルドサービスで provenance を生成 | **safe-docker はここ** |
| Level 3 | ビルドと provenance 生成が分離・隔離されている | reusable workflow で達成可能 |

### Build Provenance（ビルド来歴）

SLSA の中核概念。「このバイナリはどこで、どのソースから、どうやってビルドされたか」を記述するメタデータ。

safe-docker の provenance には以下が含まれる:

- **ソースリポジトリ**: `github.com/nekoruri/safe-docker`
- **ビルドトリガー**: タグプッシュ（`v*`）
- **ワークフロー**: `.github/workflows/release.yml`
- **ビルド環境**: GitHub Actions runner
- **成果物のダイジェスト**: SHA256 ハッシュ

## GitHub Artifact Attestations

GitHub が Sigstore を内部的に使って提供する、成果物証明の仕組み。

### 仕組み

```
[GitHub Actions ワークフロー]
    │
    ├─ ビルド → バイナリ生成
    │
    ├─ actions/attest-build-provenance@v4
    │   │
    │   ├─ GitHub OIDC トークンを取得
    │   ├─ Sigstore Fulcio から短命証明書を取得
    │   ├─ バイナリの SHA256 ダイジェストに署名
    │   ├─ SLSA Build Provenance (in-toto 形式) を生成
    │   └─ GitHub Attestations API に保存
    │
    └─ リリースにアップロード
```

### 検証時の流れ

```
[ユーザー]
    │
    ├─ バイナリをダウンロード
    │
    └─ gh attestation verify <file> --repo nekoruri/safe-docker
        │
        ├─ ファイルの SHA256 ダイジェストを計算
        ├─ GitHub Attestations API からアテステーションを取得
        ├─ Sigstore の証明書チェーンを検証
        ├─ Rekor 透明性ログでタイムスタンプを確認
        └─ ✓ 検証成功: このバイナリは正規のワークフローでビルドされた
```

### safe-docker での設定

`release.yml` に以下の3箇所を追加するだけ:

1. **permissions**: `id-token: write`（OIDC トークン取得）、`attestations: write`（アテステーション保存）
2. **ビルドステップ**: `actions/attest-build-provenance@v4` で各プラットフォームのバイナリに署名

## バイナリの検証方法

### GitHub CLI で検証（推奨）

```bash
# ダウンロード
gh release download v0.4.0 --repo nekoruri/safe-docker \
  --pattern "safe-docker-v0.4.0-x86_64-unknown-linux-gnu.tar.gz"

# アテステーション検証
gh attestation verify safe-docker-v0.4.0-x86_64-unknown-linux-gnu.tar.gz \
  --repo nekoruri/safe-docker
```

成功時の出力:
```
Loaded digest sha256:abc123... for file safe-docker-v0.4.0-x86_64-unknown-linux-gnu.tar.gz
Loaded 1 attestation from GitHub API
✓ Verification succeeded!
```

### cosign で検証（GitHub CLI 以外の選択肢）

```bash
# アテステーションバンドルをダウンロード
gh attestation download safe-docker-v0.4.0-x86_64-unknown-linux-gnu.tar.gz \
  --repo nekoruri/safe-docker

# cosign で検証
cosign verify-blob-attestation \
  --bundle <downloaded-bundle>.jsonl \
  --new-bundle-format \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp="^https://github.com/nekoruri/safe-docker/" \
  safe-docker-v0.4.0-x86_64-unknown-linux-gnu.tar.gz
```

### SHA256 チェックサムで検証（従来方式）

アテステーションに加え、リリースには `checksums-sha256.txt` も同梱される:

```bash
# ダウンロード
gh release download v0.4.0 --repo nekoruri/safe-docker

# チェックサム検証
sha256sum -c checksums-sha256.txt
```

注: チェックサム単体では配布経路の改ざんを検出できないため、アテステーション検証との併用を推奨。

## FAQ

### Q: 検証に失敗した場合はどうすればいい？

まず `gh` CLI が最新版であることを確認してください。検証失敗は以下の原因が考えられます:
- ファイルがダウンロード中に破損した → 再ダウンロード
- リリース前のビルド（タグなし）を検証しようとしている → 正式リリースのみアテステーションが付与される
- ファイルが改ざんされている → **そのバイナリを使用しないでください**

### Q: GitHub に依存しすぎでは？

Sigstore の透明性ログ（Rekor）は GitHub とは独立した公共インフラで、署名の記録は GitHub が消えても検証可能です。また、cosign を使えば GitHub CLI なしでも検証できます。ただし、アテステーションの保存・取得には現時点では GitHub API を使用しています。

### Q: SLSA Level 3 にはしないの？

現時点では Level 2 で十分と判断しています。Level 3 にはビルドと署名の完全分離（reusable workflow への移行）が必要で、cross コンパイルを含む現在のビルド構成では複雑さが増します。需要があれば将来的に対応を検討します。

### Q: ソースからビルドする場合は？

`cargo install --git` でソースからビルドする場合、ビルドプロセスはユーザーのマシン上で行われるため、アテステーションは関係しません。ソースの完全性を確認するには、リリースタグの署名検証（`git tag -v v0.x.0`）を推奨します。commit ハッシュ単体ではリポジトリ改ざんを検出できないため、署名済みタグと組み合わせて検証してください。

## 参考リンク

- [Sigstore](https://www.sigstore.dev/) - 署名基盤プロジェクト
- [SLSA](https://slsa.dev/) - サプライチェーンセキュリティフレームワーク
- [GitHub Artifact Attestations ドキュメント](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations)
- [actions/attest-build-provenance](https://github.com/actions/attest-build-provenance)
- [gh attestation verify](https://cli.github.com/manual/gh_attestation_verify)
