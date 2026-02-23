# コーディングエージェントの Docker 操作ユースケース分析

コーディングエージェント（Claude Code 等）が開発作業で Docker を使用する典型的なユースケースを網羅的に洗い出し、safe-docker の対応状況を評価する。

## 凡例

| 記号 | 意味 |
|------|------|
| :white_check_mark: | safe-docker で適切に検証される |
| :warning: | 一部のリスクが未検出 |
| :x: | 検出されない（ギャップ） |
| N/A | Docker ホストへのセキュリティリスクなし |

---

## 1. 開発環境の構築

### 1.1 コンテナ内でのコード実行

エージェントがコンテナ内でビルド、テスト、リントを実行する。

```bash
# ソースコードをマウントしてテスト実行
docker run --rm -v ~/project:/app -w /app node:18 npm test

# Python 環境でのテスト
docker run --rm -v ~/project:/app -w /app python:3.12 pytest
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| `-v ~/project:/app` のパス検証 | allow | :white_check_mark: $HOME 配下 |
| `-v /opt/data:/data` のパス検証 | deny | :white_check_mark: $HOME 外 |
| イメージ名の検証 | allow/ask | :white_check_mark: allowed_images 設定時 |
| `-w /app` のスキップ | - | :white_check_mark: is_flag_with_value |

### 1.2 データベースコンテナの起動

```bash
docker run -d --name postgres -e POSTGRES_PASSWORD=secret \
  -v pgdata:/var/lib/postgresql/data -p 5432:5432 postgres:16
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| 名前付きボリューム `pgdata` | allow | :white_check_mark: ホストパスなし |
| `-p 5432:5432` ポート公開 | allow | N/A（ホストセキュリティへの直接影響は限定的） |
| `-e` 環境変数 | - | :white_check_mark: is_flag_with_value でスキップ |

### 1.3 Docker Compose によるマルチサービス環境

```bash
docker compose up -d
docker compose down
docker compose restart
docker compose logs web
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| compose.yml の volumes 検証 | deny/allow | :white_check_mark: バインドマウント抽出 |
| compose.yml の privileged 等 | deny | :white_check_mark: 危険設定検出 |
| compose.yml の .env 変数展開 | - | :white_check_mark: 変数展開対応 |
| `docker compose down` | - | N/A（コンテナ削除のみ） |
| `docker compose restart` | - | N/A（検査対象外サブコマンド） |
| `docker compose logs` | - | N/A（読み取り専用） |

---

## 2. イメージのビルド

### 2.1 基本的なビルド

```bash
docker build -t myapp .
docker build -t myapp ~/project
docker build -f Dockerfile.dev -t myapp:dev .
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| コンテキストパス `.` (cwd) | allow/deny | :white_check_mark: host_paths で検証 |
| コンテキストパス `~/project` | allow | :white_check_mark: $HOME 配下 |
| コンテキストパス `/etc` | deny | :white_check_mark: $HOME 外 |
| `-f Dockerfile.dev` | - | :warning: **Dockerfile パスは未検証**（後述） |

### 2.2 ビルド成果物のエクスポート

```bash
# ビルド結果をホストに出力
docker build --output type=local,dest=./dist .
docker buildx build -o ./output .

# tar ファイルとしてエクスポート
docker build --output type=tar,dest=./app.tar .
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| `--output dest=./dist` のパス検証 | - | :x: **未検出。`$HOME` 外への書き込みが可能** |
| `-o ./output` の短縮形 | - | :x: **未検出** |
| `docker buildx build` サブコマンド | - | :x: **`buildx` は `Other("buildx")` として未検査** |

**ギャップ詳細**: `docker build --output type=local,dest=/etc/cron.d .` のように `$HOME` 外に成果物を書き出す攻撃が検出されない。`docker buildx build` はサブコマンドとして `buildx` が認識されるため、`build` として扱われず全てのフラグ検証がスキップされる。

### 2.3 ビルド時のシークレット・SSH アクセス

```bash
# ホストファイルをビルド時シークレットとして渡す
docker build --secret id=npmrc,src=~/.npmrc .

# SSH エージェントをビルドに渡す
docker build --ssh default .
docker build --ssh mykey=~/.ssh/id_rsa .
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| `--secret src=~/.npmrc` のパス検証 | - | :x: **未検出。任意のホストファイル読み取り可能** |
| `--ssh default` (エージェント転送) | - | :x: **未検出。SSH 鍵へのアクセスが可能** |
| `--ssh mykey=~/.ssh/id_rsa` | - | :x: **未検出** |

**ギャップ詳細**: `--secret` と `--ssh` は `parse_build_args()` で値付きフラグとしてスキップされるが、そのパス値の検証は行われない。`docker build --secret id=x,src=/etc/shadow .` でホストの機密ファイルがビルドコンテキストに露出する。

### 2.4 ビルドキャッシュの読み書き

```bash
docker build --cache-to type=local,dest=./cache .
docker build --cache-from type=local,src=./cache .
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| `--cache-to dest=` のパス | - | :x: **未検出。`$HOME` 外へのキャッシュ書き出し可能** |
| `--cache-from src=` のパス | - | :x: **未検出** |

### 2.5 Docker Compose によるビルド

```bash
docker compose build
docker compose build web
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| compose.yml の build.context 検証 | - | :x: **`compose build` は検査対象外** |
| compose.yml の build.secrets | - | :x: **未検出** |

**ギャップ詳細**: `docker compose build` は `ComposeUp`/`ComposeRun`/`ComposeCreate`/`ComposeExec` のいずれでもないため、`Other("build")` として検査がスキップされる。compose.yml 内の `build.context` が `$HOME` 外を指す場合でも検出されない。

---

## 3. ファイルのコピー

### 3.1 docker cp

```bash
# ホストからコンテナへ
docker cp ~/project/config.json mycontainer:/app/

# コンテナからホストへ
docker cp mycontainer:/app/build/ ~/project/dist/
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| ホストパスの検証 | deny/allow | :white_check_mark: host_paths で検証 |
| コンテナパスのスキップ | - | :white_check_mark: `container:path` 判定 |
| `/etc/passwd` からのコピー | deny | :white_check_mark: $HOME 外 |

### 3.2 docker compose cp

```bash
docker compose cp web:/app/dist ./dist
docker compose cp ./config.json web:/app/
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| `compose cp` のパス検証 | - | :x: **`compose cp` は検査対象外** |

**ギャップ詳細**: `docker compose cp /etc/passwd web:/tmp/` が検出されない。compose のサブコマンドとして `cp` は処理されていない。

---

## 4. イメージ・コンテナのエクスポート/インポート

### 4.1 イメージの保存・読み込み

```bash
# イメージをファイルに保存
docker save -o ~/images/myapp.tar myapp:latest
docker save myapp:latest > ~/images/myapp.tar

# ファイルからイメージを読み込み
docker load -i ~/images/myapp.tar
docker load < ~/images/myapp.tar
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| `docker save -o /path` のパス検証 | - | :x: **未検出。`$HOME` 外への書き込み可能** |
| `docker load -i /path` のパス検証 | - | :x: **未検出。`$HOME` 外からの読み取り可能** |

**ギャップ詳細**: `docker save -o /tmp/rootfs.tar` や `docker load -i /etc/malicious.tar` はサブコマンドが `Other("save")`/`Other("load")` として無視される。ホストファイルシステムへの読み書きが検証されない。

### 4.2 コンテナのエクスポート/インポート

```bash
# コンテナのファイルシステムをエクスポート
docker export -o ~/backup/container.tar mycontainer
docker export mycontainer > ~/backup/container.tar

# ファイルからイメージとしてインポート
docker import ~/backup/container.tar myimage:restored
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| `docker export -o /path` のパス検証 | - | :x: **未検出** |
| `docker import /path` のパス検証 | - | :x: **未検出** |

---

## 5. コンテナの操作

### 5.1 コンテナ内でのコマンド実行

```bash
docker exec -it mycontainer bash
docker exec mycontainer python manage.py migrate
docker compose exec web rails db:migrate
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| `docker exec` のフラグ検証 | - | N/A（exec にはマウント/特権フラグなし） |
| `docker compose exec` | - | :white_check_mark: ComposeExec（ファイル解析なし、正しい挙動） |

**補足**: `docker exec` はすでに実行中のコンテナで動作するため、マウントや特権に関するフラグはない。ただし、コンテナ作成時に危険なマウントが行われていた場合、exec からその内容にアクセスできてしまう点は構造的な制限。

### 5.2 コンテナのライフサイクル管理

```bash
docker start mycontainer
docker stop mycontainer
docker restart mycontainer
docker rm mycontainer
docker rm -f $(docker ps -aq)
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| コンテナ起動/停止/削除 | - | N/A（ホストファイルシステムへの影響なし） |

### 5.3 ログ・監視

```bash
docker logs -f mycontainer
docker stats
docker top mycontainer
docker inspect mycontainer
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| ログ・統計情報の閲覧 | - | N/A（読み取り専用） |
| `docker inspect` の情報開示 | - | N/A（マウント情報等は表示されるが変更不可） |

---

## 6. ボリューム管理

### 6.1 名前付きボリュームの作成・使用

```bash
docker volume create mydata
docker run -v mydata:/data ubuntu
docker volume rm mydata
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| 名前付きボリューム | allow | :white_check_mark: ホストパスなしとして許可 |

### 6.2 ドライバオプションによるホストパスバインド

```bash
# 名前付きボリュームに見せかけたホストパスバインド
docker volume create --driver local \
  --opt type=none --opt o=bind --opt device=/etc myvolume
docker run -v myvolume:/data ubuntu
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| `docker volume create --opt device=/etc` | - | :x: **未検出（既知の制限事項）** |
| 後続の `docker run -v myvolume:/data` | allow | :warning: **名前付きボリュームとして許可される** |

**ギャップ詳細**: SECURITY.md に記載済みの既知の制限。`docker volume create` と `docker run -v` が別コマンドで実行されるため、CLI hook レベルでの完全な検出は構造的に困難。Layer 2 (OPA) での防御が必要。

---

## 7. ネットワーク管理

### 7.1 ネットワークの作成・接続

```bash
docker network create mynet
docker network connect mynet mycontainer
docker network rm mynet
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| ネットワーク操作 | - | N/A（ホストファイルシステムへの直接影響なし） |

---

## 8. レジストリ操作

### 8.1 イメージの push/pull

```bash
docker pull ubuntu:22.04
docker tag myapp:latest registry.example.com/myapp:v1
docker push registry.example.com/myapp:v1
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| イメージの pull/push/tag | - | N/A（ホストファイルシステムへの直接影響なし） |

### 8.2 レジストリへのログイン

```bash
docker login registry.example.com
docker login -u user -p token registry.example.com
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| `~/.docker/config.json` への認証情報書き込み | - | :warning: **検出されないが、$HOME 配下への書き込みなのでリスクは限定的** |

---

## 9. Docker-in-Docker / Docker ソケット

### 9.1 Docker ソケットのマウント

```bash
docker run -v /var/run/docker.sock:/var/run/docker.sock docker:cli docker ps
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| Docker ソケットのマウント | deny | :white_check_mark: Docker ソケット検出 |
| パストラバーサル (`/var/run/docker.sock/.`) | deny | :white_check_mark: 正規化で検出 |

---

## 10. システム管理

### 10.1 クリーンアップ

```bash
docker system prune -af
docker image prune -a
docker container prune
docker volume prune
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| システムクリーンアップ | - | N/A（ホストファイルシステムの破壊リスクはないが、Docker リソースの意図しない削除はあり得る） |

### 10.2 Docker コンテキストの変更

```bash
docker context create remote --docker "host=tcp://remote:2375"
docker context use remote
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| リモート Docker デーモンへの接続設定 | - | :warning: **検出されない。リモートデーモンには safe-docker のポリシーが適用されない可能性** |

---

## 11. Docker プラグイン

### 11.1 プラグインのインストール

```bash
docker plugin install vieux/sshfs
docker plugin enable myplugin
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| プラグインのインストール | - | :x: **未検出。プラグインはホストの高権限を取得する可能性** |

---

## 12. ホストファイルを読み取るフラグ

### 12.1 --env-file

```bash
docker run --env-file ~/project/.env myapp
docker run --env-file /etc/environment myapp
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| `--env-file ~/project/.env` | - | :x: **パスが未検証。`$HOME` 配下なら低リスク** |
| `--env-file /etc/environment` | - | :x: **パスが未検証。`$HOME` 外のファイル読み取り可能** |

**ギャップ詳細**: `--env-file` は `is_flag_with_value()` に含まれていないため、次の引数が通常の値としてスキップされる（結果的にパス値は消費される）。しかしパス検証は行われない。`docker run --env-file /etc/shadow myapp` でホストの機密ファイルの内容がコンテナ環境変数に設定される。

### 12.2 --cidfile

```bash
docker run --cidfile ~/tmp/container.id myapp
docker run --cidfile /tmp/container.id myapp
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| `--cidfile` によるファイル書き込み | - | :warning: **`is_flag_with_value()` でスキップされるがパス未検証。書き込まれる内容はコンテナ ID のみなのでリスクは低** |

### 12.3 --label-file

```bash
docker run --label-file ~/project/labels.txt myapp
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| `--label-file` によるファイル読み取り | - | :x: **`is_flag_with_value()` に未登録。パスも未検証** |

---

## 13. シェル間接実行パターン

### 13.1 検出されるパターン

```bash
eval "docker run -v /etc:/data ubuntu"              # ✓ 検出
bash -c "docker run -v /etc:/data ubuntu"            # ✓ 検出
sh -c 'docker run -v /etc:/data ubuntu'              # ✓ 検出
sudo docker run -v /etc:/data ubuntu                 # ✓ 検出
xargs docker run ...                                 # ✓ 検出
DOCKER_HOST=tcp://... docker run -v /etc:/data ubuntu # ✓ 検出
```

### 13.2 検出されないパターン

```bash
# 変数に格納されたコマンド
CMD="docker run -v /etc:/data ubuntu"; $CMD

# スクリプトファイル経由
echo "docker run -v /etc:/data ubuntu" > /tmp/run.sh
bash /tmp/run.sh

# エイリアス/関数
alias d=docker; d run -v /etc:/data ubuntu

# ヒアドキュメント
bash <<'EOF'
docker run -v /etc:/data ubuntu
EOF

# プロセス置換
source <(echo "docker run -v /etc:/data ubuntu")

# Python/Node 等のスクリプト言語経由
python -c "import os; os.system('docker run -v /etc:/data ubuntu')"

# if/for/while 内のコマンド
if true; then docker run -v /etc:/data ubuntu; fi
for i in 1; do docker run -v /etc:/data ubuntu; done
```

| パターン | 対応状況 |
|----------|----------|
| 変数展開 | :warning: パス内の変数は ask、コマンド変数は未検出 |
| スクリプトファイル | :x: Layer 2 (OPA) で防御 |
| エイリアス/関数 | :x: Layer 2 (OPA) で防御 |
| ヒアドキュメント | :x: 既知の制限 |
| プロセス置換 | :x: Layer 2 (OPA) で防御 |
| 他言語スクリプト | :x: Layer 2 (OPA) で防御 |
| 制御構文内コマンド | :x: シェルパーサーの制限 |

---

## 14. buildx 固有の機能

### 14.1 Buildx エンタイトルメント

```bash
# セキュリティサンドボックスの無効化
docker buildx build --allow security.insecure .

# ビルド中のホストネットワーク使用
docker buildx build --allow network.host .

# ビルド中のホストファイルシステムアクセス
docker buildx build --allow fs.read=/etc .
docker buildx build --allow fs.write=/tmp .
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| `--allow security.insecure` | - | :x: **`buildx` サブコマンド自体が未検出** |
| `--allow network.host` | - | :x: **同上** |
| `--allow fs.read=/path` | - | :x: **同上** |
| `--allow fs.write=/path` | - | :x: **同上** |

### 14.2 Buildx bake

```bash
docker buildx bake --set '*.output=type=local,dest=/tmp'
```

| リスク | 判定 | 対応状況 |
|--------|------|----------|
| `docker buildx bake` | - | :x: **未検出** |

---

## ギャップ一覧（優先度別）

### 高優先度（ホストファイルシステムへの直接的な読み書き）

| # | ギャップ | 影響 | 推奨対策 |
|---|---------|------|----------|
| G-1 | `docker buildx build` が未検出 | ビルドの全フラグ検証がバイパスされる | `buildx` の次の `build`/`bake` を Docker サブコマンドとして認識 |
| G-2 | `docker build --output` / `-o` のパス検証 | `$HOME` 外へのファイル書き出し | `--output` 内の `dest=` パスを host_paths に追加 |
| G-3 | `docker save -o` / `docker export -o` のパス検証 | `$HOME` 外へのファイル書き込み | `save`/`export` サブコマンドの `-o` パスを検証 |
| G-4 | `docker load -i` / `docker import` のパス検証 | `$HOME` 外からのファイル読み取り | `load`/`import` サブコマンドのパスを検証 |
| G-5 | `docker build --secret src=` のパス検証 | 任意のホストファイル読み取り | `--secret` の `src=` パスを host_paths に追加 |
| G-6 | `docker build --ssh` のキーパス検証 | SSH 鍵ファイルへのアクセス | `--ssh` の `KEY=PATH` パスを検証 |
| G-7 | `docker compose cp` が未検出 | compose 経由のファイルコピー | compose のサブコマンドに `cp` を追加 |
| G-8 | `docker compose build` が未検出 | compose 経由のビルドが無検査 | compose のサブコマンドに `build` を追加し、compose.yml の `build.context` を検証 |

### 中優先度（限定的なファイルアクセスまたは間接的リスク）

| # | ギャップ | 影響 | 推奨対策 |
|---|---------|------|----------|
| G-9 | `--env-file` のパス検証 | `$HOME` 外のファイル読み取り | `--env-file` を個別検出しパス検証 |
| G-10 | `--label-file` が `is_flag_with_value()` に未登録 | フラグパースの誤動作 | リストに追加 |
| G-11 | `docker build -f` / `--file` のパス検証 | `$HOME` 外の Dockerfile 読み取り | `-f` パスを host_paths に追加 |
| G-12 | `docker build --iidfile` / `--metadata-file` のパス検証 | `$HOME` 外への小ファイル書き込み | パス検証を追加 |
| G-13 | `docker build --cache-to` / `--cache-from` のパス検証 | `$HOME` 外へのキャッシュ読み書き | `type=local` 時の `dest=`/`src=` パスを検証 |
| G-14 | `docker context create` によるリモート接続 | 他ホストの Docker デーモン操作 | `context` サブコマンドの ask 検討 |
| G-15 | `docker plugin install` の検出 | 高権限プラグインのインストール | `plugin install` を ask に |

### 低優先度（リスクが限定的またはレアケース）

| # | ギャップ | 影響 | 推奨対策 |
|---|---------|------|----------|
| G-16 | `--cidfile` のパス検証 | コンテナ ID のみの小ファイル書き込み | 中リスクへの格上げを検討 |
| G-17 | `docker volume create --opt device=` | 名前付きボリューム経由のバインド | Layer 2 (OPA) で防御（既知の制限） |
| G-18 | `buildx build --allow` エンタイトルメント | ビルド時のセキュリティ緩和 | G-1 解決後に対応 |

---

## 対応マトリクス: Docker サブコマンドと safe-docker の検査範囲

| サブコマンド | 検査対象 | フラグ検証 | パス検証 | Compose 解析 |
|-------------|---------|-----------|---------|-------------|
| `docker run` | :white_check_mark: | :white_check_mark: 全フラグ | :white_check_mark: `-v`, `--mount` | - |
| `docker create` | :white_check_mark: | :white_check_mark: 全フラグ | :white_check_mark: `-v`, `--mount` | - |
| `docker build` | :white_check_mark: | - | :white_check_mark: コンテキストのみ | - |
| `docker cp` | :white_check_mark: | - | :white_check_mark: SRC/DEST | - |
| `docker compose up` | :white_check_mark: | - | :white_check_mark: | :white_check_mark: |
| `docker compose run` | :white_check_mark: | - | :white_check_mark: `-v` | :white_check_mark: |
| `docker compose create` | :white_check_mark: | - | :white_check_mark: | :white_check_mark: |
| `docker compose exec` | :white_check_mark: | - | - | - (正しい挙動) |
| `docker compose build` | :x: | - | - | - |
| `docker compose cp` | :x: | - | - | - |
| `docker buildx build` | :x: | - | - | - |
| `docker buildx bake` | :x: | - | - | - |
| `docker save` | :x: | - | - | - |
| `docker load` | :x: | - | - | - |
| `docker export` | :x: | - | - | - |
| `docker import` | :x: | - | - | - |
| `docker exec` | N/A | N/A | N/A | - |
| `docker start/stop/rm` | N/A | N/A | N/A | - |
| `docker pull/push/tag` | N/A | N/A | N/A | - |
| `docker logs/inspect` | N/A | N/A | N/A | - |
| `docker volume create` | :x: | - | - | - |
| `docker context create` | :x: | - | - | - |
| `docker plugin install` | :x: | - | - | - |
| `docker login` | N/A | N/A | N/A | - |

---

## safe-docker で検査すべき「値付きフラグ」のうち、パス検証が必要なもの

`docker run` / `docker create`:

| フラグ | ホストアクセス | 現在の対応 | 推奨 |
|--------|-------------|-----------|------|
| `-v` / `--volume` | 読み書き | :white_check_mark: 検証済み | - |
| `--mount` | 読み書き | :white_check_mark: 検証済み | - |
| `--env-file` | 読み取り | :x: スキップのみ | パス検証追加 |
| `--label-file` | 読み取り | :x: 未登録 | 登録 + パス検証 |
| `--cidfile` | 書き込み（ID のみ） | :warning: スキップのみ | パス検証検討 |
| `--log-opt path=` | 書き込み | :warning: スキップのみ | `path=` の検証検討 |

`docker build`:

| フラグ | ホストアクセス | 現在の対応 | 推奨 |
|--------|-------------|-----------|------|
| コンテキストパス | 読み取り | :white_check_mark: 検証済み | - |
| `-f` / `--file` | 読み取り | :x: スキップのみ | パス検証追加 |
| `--output` / `-o` | 書き込み | :x: スキップのみ | パス検証追加 |
| `--secret src=` | 読み取り | :x: スキップのみ | パス検証追加 |
| `--ssh KEY=PATH` | 読み取り | :x: スキップのみ | パス検証追加 |
| `--iidfile` | 書き込み | :x: スキップのみ | パス検証追加 |
| `--metadata-file` | 書き込み | :x: 未登録 | 登録 + パス検証 |
| `--cache-to type=local` | 書き込み | :x: スキップのみ | パス検証追加 |
| `--cache-from type=local` | 読み取り | :x: スキップのみ | パス検証追加 |

---

## 構造的な制限と Layer 2 による防御

以下のパターンは safe-docker (Layer 1) では根本的に防御できず、Layer 2 (OPA Docker AuthZ) での防御が必要:

| 制限 | 理由 | Layer 2 の対応 |
|------|------|---------------|
| スクリプトファイル経由の実行 | hook はコマンド文字列のみ検査 | OPA が daemon レベルで全リクエスト検査 |
| エイリアス/シェル関数 | シェル内で展開されてから docker CLI が起動 | 同上 |
| コンパイルバイナリ内からの API 呼び出し | CLI 経由でない | 同上 |
| Docker API 直接呼び出し (curl 等) | CLI 経由でない | Docker ソケットマウント禁止 + OPA |
| `docker volume create` + 後続 `docker run` | 2 コマンドの関連づけ不可 | OPA で volume の driver opts を検査 |
| 他言語スクリプト (Python subprocess 等) | hook はトップレベルコマンドのみ | 同上 |

---

## まとめ

safe-docker は、コーディングエージェントの **最も一般的な Docker 操作パターン**（`docker run`/`create` のマウントと危険フラグ、`docker cp`、`docker build` のコンテキスト、`docker compose` の設定）に対して適切な検証を行っている。

一方で、**ビルド出力/シークレット/キャッシュ**（G-1〜G-6）、**イメージのエクスポート/インポート**（G-3〜G-4）、**compose の build/cp サブコマンド**（G-7〜G-8）については検出ギャップが存在する。これらは実際のコーディングエージェントの開発ワークフローでも使用頻度が高い操作であり、対応の優先度は高い。

Layer 2 (OPA) は、safe-docker が構造的に検出できないパターン（スクリプト経由、API 直接呼び出し等）に対する最終防衛線として不可欠であり、両レイヤーの組み合わせにより包括的な防御を実現する。
