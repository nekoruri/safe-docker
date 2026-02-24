# 監査ログ動作確認手順書

## 前提

- 現在のブランチ: `feat/audit-logging`
- ユニットテスト・統合テスト・セキュリティテスト・proptest は全合格済み (243 テスト)
- 本手順は **手動 E2E 確認** と **OTel Collector 統合確認** をカバーする

## 0. ビルド

```bash
# OTLP feature 込みでリリースビルド
cargo build --release --features otlp

# バイナリパス (以降 $BIN で参照)
BIN=./target/release/safe-docker
```

## 1. JSONL 出力 — 基本動作確認

### 1.1 環境変数での有効化 (設定ファイルなし)

```bash
# 前回の出力をクリア
rm -f ~/.local/share/safe-docker/audit.jsonl

# deny ケース: $HOME 外マウント
SAFE_DOCKER_AUDIT=1 sh -c '
echo "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"docker run -v /etc:/data ubuntu\"},\"cwd\":\"/tmp\"}" \
| '"$BIN"
```

**確認項目:**
```bash
# 1行出力されていること
wc -l ~/.local/share/safe-docker/audit.jsonl
# → 1

# JSON としてパース可能であること
jq . ~/.local/share/safe-docker/audit.jsonl

# 以下のフィールドを確認
jq '{decision, command, docker_subcommand, docker_image, bind_mounts, dangerous_flags, cwd, pid, host_name, environment}' \
  ~/.local/share/safe-docker/audit.jsonl
```

**期待値:**
```json
{
  "decision": "deny",
  "command": "docker run -v /etc:/data ubuntu",
  "docker_subcommand": "run",
  "docker_image": "ubuntu",
  "bind_mounts": ["/etc"],
  "dangerous_flags": [],
  "cwd": "/tmp",
  "pid": "<非ゼロ整数>",
  "host_name": "<ホスト名>",
  "environment": "development"
}
```

### 1.2 3種の判定タイプ

```bash
rm -f ~/.local/share/safe-docker/audit.jsonl

# (a) allow: docker ps (マウントなし)
SAFE_DOCKER_AUDIT=1 sh -c '
echo "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"docker ps\"},\"cwd\":\"/tmp\"}" \
| '"$BIN"

# (b) deny: --privileged
SAFE_DOCKER_AUDIT=1 sh -c '
echo "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"docker run --privileged ubuntu\"},\"cwd\":\"/tmp\"}" \
| '"$BIN"

# (c) ask: 機密パスマウント (.ssh)
HOME_DIR=$(echo ~)
SAFE_DOCKER_AUDIT=1 sh -c '
echo "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"docker run -v '"$HOME_DIR"'/.ssh:/keys ubuntu\"},\"cwd\":\"/tmp\"}" \
| '"$BIN"
```

**確認項目:**
```bash
# 3行出力されていること
wc -l ~/.local/share/safe-docker/audit.jsonl
# → 3

# 各 decision 値を確認
jq -r .decision ~/.local/share/safe-docker/audit.jsonl
# → allow
# → deny
# → ask

# allow イベントには reason がないこと
jq 'select(.decision == "allow") | has("reason")' ~/.local/share/safe-docker/audit.jsonl
# → false

# deny/ask イベントには reason があること
jq 'select(.decision != "allow") | .reason' ~/.local/share/safe-docker/audit.jsonl
# → 非 null の文字列
```

### 1.3 session_id の伝播

```bash
rm -f ~/.local/share/safe-docker/audit.jsonl

SAFE_DOCKER_AUDIT=1 sh -c '
echo "{\"session_id\":\"my-session-abc\",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"docker ps\"},\"cwd\":\"/tmp\"}" \
| '"$BIN"

jq -r .session_id ~/.local/share/safe-docker/audit.jsonl
# → my-session-abc
```

### 1.4 非 Docker コマンド

```bash
rm -f ~/.local/share/safe-docker/audit.jsonl

# 非 docker コマンドは allow (stdout 無出力) → 監査ログも docker 情報なし
SAFE_DOCKER_AUDIT=1 sh -c '
echo "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"ls -la /tmp\"},\"cwd\":\"/tmp\"}" \
| '"$BIN"

jq '{decision, docker_subcommand, docker_image, bind_mounts}' \
  ~/.local/share/safe-docker/audit.jsonl
```

**期待値:**
```json
{
  "decision": "allow",
  "docker_subcommand": null,
  "docker_image": null,
  "bind_mounts": []
}
```

### 1.5 非 Bash ツール (allow、監査ログなし)

```bash
rm -f ~/.local/share/safe-docker/audit.jsonl

SAFE_DOCKER_AUDIT=1 sh -c '
echo "{\"tool_name\":\"Read\",\"tool_input\":{},\"cwd\":\"/tmp\"}" \
| '"$BIN"

# 監査ログファイルが作成されない (非 Bash は extract_command で None → main() が即 return)
test -f ~/.local/share/safe-docker/audit.jsonl && echo "FAIL: file exists" || echo "OK: no audit log"
```

### 1.6 SAFE_DOCKER_ENV 環境変数

```bash
rm -f ~/.local/share/safe-docker/audit.jsonl

SAFE_DOCKER_AUDIT=1 SAFE_DOCKER_ENV=production sh -c '
echo "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"docker ps\"},\"cwd\":\"/tmp\"}" \
| '"$BIN"

jq -r .environment ~/.local/share/safe-docker/audit.jsonl
# → production
```

## 2. config.toml による設定

### 2.1 設定ファイルでの有効化

```bash
# テスト用設定ディレクトリ
mkdir -p /tmp/safe-docker-test
cat > /tmp/safe-docker-test/config.toml << 'EOF'
[audit]
enabled = true
format = "jsonl"
jsonl_path = "/tmp/safe-docker-test/audit.jsonl"
otlp_path = "/tmp/safe-docker-test/audit-otlp.jsonl"
EOF

# 注意: Config::load() はデフォルトパス (~/.config/safe-docker/config.toml) を読む。
# テスト用には一時的にデフォルトパスに配置する必要がある。
mkdir -p ~/.config/safe-docker
cp /tmp/safe-docker-test/config.toml ~/.config/safe-docker/config.toml

sh -c '
echo "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"docker ps\"},\"cwd\":\"/tmp\"}" \
| '"$BIN"

jq . /tmp/safe-docker-test/audit.jsonl

# テスト後クリーンアップ
rm ~/.config/safe-docker/config.toml
```

## 3. OTLP 出力 — 構造検証

### 3.1 OTLP JSONL の出力

```bash
rm -f /tmp/safe-docker-test/audit-otlp.jsonl

mkdir -p ~/.config/safe-docker
cat > ~/.config/safe-docker/config.toml << 'EOF'
[audit]
enabled = true
format = "otlp"
jsonl_path = "/tmp/safe-docker-test/audit.jsonl"
otlp_path = "/tmp/safe-docker-test/audit-otlp.jsonl"
EOF

# deny ケース
sh -c '
echo "{\"session_id\":\"sess-otlp\",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"docker run --privileged -v /etc:/data ubuntu\"},\"cwd\":\"/home/user\"}" \
| '"$BIN"

rm ~/.config/safe-docker/config.toml
```

### 3.2 OTLP JSON 構造の検証

```bash
# ExportLogsServiceRequest のトップレベル構造
jq 'keys' /tmp/safe-docker-test/audit-otlp.jsonl
# → ["resourceLogs"]

# Resource 属性の確認
jq '.resourceLogs[0].resource.attributes[] | {key, value: .value.stringValue}' \
  /tmp/safe-docker-test/audit-otlp.jsonl
```

**期待値 (Resource 属性):**
```json
{"key": "service.name",                 "value": "safe-docker"}
{"key": "service.version",              "value": "0.1.0"}
{"key": "deployment.environment.name",  "value": "development"}
{"key": "host.name",                    "value": "<ホスト名>"}
```

```bash
# LogRecord の確認
jq '.resourceLogs[0].scopeLogs[0].logRecords[0] | {
  timeUnixNano,
  observedTimeUnixNano,
  severityNumber,
  severityText,
  body
}' /tmp/safe-docker-test/audit-otlp.jsonl
```

**期待値 (deny の場合):**
```json
{
  "timeUnixNano": "<非ゼロ文字列>",
  "observedTimeUnixNano": "<同上>",
  "severityNumber": 17,
  "severityText": "ERROR",
  "body": {"stringValue": "<reason 文字列>"}
}
```

```bash
# LogRecord 属性の確認
jq '[.resourceLogs[0].scopeLogs[0].logRecords[0].attributes[] | {key, value: (.value.stringValue // .value.intValue // .value.arrayValue)}]' \
  /tmp/safe-docker-test/audit-otlp.jsonl
```

**期待される属性キー:**
- `decision` → `"deny"`
- `command` → `"docker run --privileged -v /etc:/data ubuntu"`
- `cwd` → `"/home/user"`
- `session_id` → `"sess-otlp"`
- `docker.subcommand` → `"run"`
- `docker.image` → `"ubuntu"`
- `docker.bind_mounts` → 配列 `["/etc"]`
- `docker.dangerous_flags` → 配列 `["--privileged"]`
- `process.pid` → 整数

### 3.3 Severity マッピングの全パターン確認

```bash
rm -f /tmp/safe-docker-test/audit-otlp.jsonl

mkdir -p ~/.config/safe-docker
cat > ~/.config/safe-docker/config.toml << 'EOF'
[audit]
enabled = true
format = "otlp"
jsonl_path = "/tmp/safe-docker-test/audit.jsonl"
otlp_path = "/tmp/safe-docker-test/audit-otlp.jsonl"
EOF

# allow (INFO=9)
sh -c 'echo "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"docker ps\"},\"cwd\":\"/tmp\"}" | '"$BIN"

# deny (ERROR=17)
sh -c 'echo "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"docker run --privileged ubuntu\"},\"cwd\":\"/tmp\"}" | '"$BIN"

# ask (WARN=13)
HOME_DIR=$(echo ~)
sh -c 'echo "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"docker run -v '"$HOME_DIR"'/.ssh:/keys ubuntu\"},\"cwd\":\"/tmp\"}" | '"$BIN"

rm ~/.config/safe-docker/config.toml

# 各行の severityNumber を確認
jq '.resourceLogs[0].scopeLogs[0].logRecords[0] | {severityNumber, severityText}' \
  /tmp/safe-docker-test/audit-otlp.jsonl
```

**期待値 (3行):**
```
{"severityNumber": 9,  "severityText": "INFO"}
{"severityNumber": 17, "severityText": "ERROR"}
{"severityNumber": 13, "severityText": "WARN"}
```

### 3.4 format = "both" の確認

```bash
rm -f /tmp/safe-docker-test/audit.jsonl /tmp/safe-docker-test/audit-otlp.jsonl

mkdir -p ~/.config/safe-docker
cat > ~/.config/safe-docker/config.toml << 'EOF'
[audit]
enabled = true
format = "both"
jsonl_path = "/tmp/safe-docker-test/audit.jsonl"
otlp_path = "/tmp/safe-docker-test/audit-otlp.jsonl"
EOF

sh -c 'echo "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"docker ps\"},\"cwd\":\"/tmp\"}" | '"$BIN"

rm ~/.config/safe-docker/config.toml

# 両方のファイルに1行ずつ出力されていること
wc -l /tmp/safe-docker-test/audit.jsonl /tmp/safe-docker-test/audit-otlp.jsonl
# → 1 audit.jsonl
# → 1 audit-otlp.jsonl
```

## 4. OTel Collector 統合確認

OTLP JSON 出力が実際に OTel Collector で受信・処理できることを確認する。

### 4.1 Collector 設定ファイル

```bash
mkdir -p /tmp/otel-collector-test

cat > /tmp/otel-collector-test/config.yaml << 'EOF'
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318

exporters:
  debug:
    verbosity: detailed
  file/logs:
    path: /otel-data/output.json

service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [debug, file/logs]
EOF

mkdir -p /tmp/otel-collector-test/otel-data
```

### 4.2 Collector 起動

```bash
docker run -d --name otel-collector-test \
  -v /tmp/otel-collector-test/config.yaml:/etc/otelcol/config.yaml \
  -v /tmp/otel-collector-test/otel-data:/otel-data \
  -p 4318:4318 \
  otel/opentelemetry-collector:latest
```

### 4.3 OTLP JSON を Collector に送信

safe-docker が出力した OTLP JSONL の各行は `ExportLogsServiceRequest` なので、そのまま OTLP/HTTP エンドポイントに POST できる。

```bash
# まず safe-docker で OTLP 出力を生成 (手順 3.1 の結果を使用)
OTLP_LINE=$(head -1 /tmp/safe-docker-test/audit-otlp.jsonl)

# Collector の OTLP/HTTP エンドポイントに送信
curl -s -w "\nHTTP %{http_code}\n" \
  -X POST http://localhost:4318/v1/logs \
  -H "Content-Type: application/json" \
  -d "$OTLP_LINE"
```

**期待値:**
- HTTP 200 が返ること
- レスポンスボディが `{}` または `{"partialSuccess":{}}` であること

### 4.4 Collector の出力を確認

```bash
# debug exporter の出力をログで確認
docker logs otel-collector-test 2>&1 | grep -A 20 "LogRecord"

# file exporter の出力を確認
jq . /tmp/otel-collector-test/otel-data/output.json
```

**確認項目:**
- `service.name: safe-docker` が Resource 属性に含まれていること
- LogRecord の `SeverityNumber`/`SeverityText` が正しいこと
- 属性 (`decision`, `command`, `docker.subcommand` 等) が正しく受信されていること

### 4.5 クリーンアップ

```bash
docker stop otel-collector-test && docker rm otel-collector-test
rm -rf /tmp/otel-collector-test
```

## 5. エッジケース

### 5.1 監査ログ無効時 — ゼロオーバーヘッド

```bash
rm -f ~/.local/share/safe-docker/audit.jsonl

# SAFE_DOCKER_AUDIT 未設定、config.toml に audit セクションなし
sh -c '
echo "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"docker ps\"},\"cwd\":\"/tmp\"}" \
| '"$BIN"

# ファイルが作成されないこと
test -f ~/.local/share/safe-docker/audit.jsonl && echo "FAIL" || echo "OK: no file created"
```

### 5.2 ディレクトリ自動作成

```bash
rm -rf /tmp/safe-docker-deep-test

SAFE_DOCKER_AUDIT=1 sh -c '
echo "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"docker ps\"},\"cwd\":\"/tmp\"}" \
| '"$BIN"

# デフォルトパスのディレクトリが自動作成されること
test -d ~/.local/share/safe-docker && echo "OK: dir created" || echo "FAIL"
```

### 5.3 書き込み不可パスでの graceful failure

```bash
mkdir -p ~/.config/safe-docker
cat > ~/.config/safe-docker/config.toml << 'EOF'
[audit]
enabled = true
format = "jsonl"
jsonl_path = "/root/cannot-write-here/audit.jsonl"
EOF

# hook レスポンス自体は正常に返ること (audit 失敗が Decision に影響しない)
OUTPUT=$(sh -c '
echo "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"docker run --privileged ubuntu\"},\"cwd\":\"/tmp\"}" \
| '"$BIN" 2>/dev/null)

echo "$OUTPUT" | jq .hookSpecificOutput.permissionDecision
# → "deny" (audit 失敗に関わらず正しい判定)

rm ~/.config/safe-docker/config.toml
```

### 5.4 OTLP feature なしビルドでの otlp format 指定

```bash
# feature なしでビルド
cargo build --release
BIN_NO_OTLP=./target/release/safe-docker

mkdir -p ~/.config/safe-docker
cat > ~/.config/safe-docker/config.toml << 'EOF'
[audit]
enabled = true
format = "otlp"
jsonl_path = "/tmp/safe-docker-test/audit.jsonl"
otlp_path = "/tmp/safe-docker-test/audit-otlp.jsonl"
EOF

# 実行 — stderr に警告が出るが、パニックやエラーにならないこと
OUTPUT=$(RUST_LOG=warn sh -c '
echo "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"docker ps\"},\"cwd\":\"/tmp\"}" \
| '"$BIN_NO_OTLP" 2>/tmp/safe-docker-test/stderr.log)

# OTLP ファイルが作成されないこと
test -f /tmp/safe-docker-test/audit-otlp.jsonl && echo "FAIL" || echo "OK: no otlp file"

# stderr に警告メッセージがあること
grep -q "otlp.*feature.*not.*enabled" /tmp/safe-docker-test/stderr.log && echo "OK: warning logged" || echo "WARN: no warning"

rm ~/.config/safe-docker/config.toml
```

## 6. パフォーマンス確認

```bash
# ベンチマーク実行 (audit 無効のデフォルト状態)
cargo bench

# 結果を確認し、以前の結果と比較して大きなリグレッションがないことを確認
# (audit 無効時のオーバーヘッドは is_enabled() の条件チェックのみ)
```

## 7. 自動テストの再確認

```bash
# 全テスト (OTLP 含む)
cargo test --features otlp
# → 243 テスト全合格

# Clippy
cargo clippy --features otlp -- -D warnings
# → 警告なし
```

## 8. チェックリスト

| # | 確認項目 | 手順 | 結果 |
|---|---------|------|------|
| 1 | JSONL: deny イベント出力 | 1.1 | |
| 2 | JSONL: allow/deny/ask 全判定タイプ | 1.2 | |
| 3 | JSONL: session_id 伝播 | 1.3 | |
| 4 | JSONL: 非 Docker コマンド | 1.4 | |
| 5 | JSONL: 非 Bash ツール (ログなし) | 1.5 | |
| 6 | JSONL: SAFE_DOCKER_ENV 反映 | 1.6 | |
| 7 | config.toml での有効化 | 2.1 | |
| 8 | OTLP: ExportLogsServiceRequest 構造 | 3.2 | |
| 9 | OTLP: Resource 属性 (service.name 等) | 3.2 | |
| 10 | OTLP: Severity マッピング (INFO/WARN/ERROR) | 3.3 | |
| 11 | OTLP: LogRecord 属性 (decision, command 等) | 3.2 | |
| 12 | OTLP: format = "both" で両方出力 | 3.4 | |
| 13 | OTel Collector: HTTP POST で受信成功 | 4.3 | |
| 14 | OTel Collector: ログ内容が正しく受信 | 4.4 | |
| 15 | エッジ: 無効時はファイル未作成 | 5.1 | |
| 16 | エッジ: ディレクトリ自動作成 | 5.2 | |
| 17 | エッジ: 書き込み不可でも判定は正常 | 5.3 | |
| 18 | エッジ: otlp feature なしで otlp 指定 | 5.4 | |
| 19 | パフォーマンス: リグレッションなし | 6 | |
| 20 | 自動テスト: 全合格 | 7 | |

## クリーンアップ

```bash
rm -rf /tmp/safe-docker-test
rm -rf /tmp/otel-collector-test
rm -f ~/.local/share/safe-docker/audit.jsonl
rm -f ~/.local/share/safe-docker/audit-otlp.jsonl
rm -f ~/.config/safe-docker/config.toml
```
