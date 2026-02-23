/// シェルコマンドをパイプ/チェインで分割し、各セグメントを返す。
/// クォート内のセパレータは分割しない。
pub fn split_commands(command: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut chars = command.chars().peekable();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escape_next = false;

    while let Some(ch) = chars.next() {
        if escape_next {
            current.push(ch);
            escape_next = false;
            continue;
        }

        if ch == '\\' && !in_single_quote {
            escape_next = true;
            current.push(ch);
            continue;
        }

        if ch == '\'' && !in_double_quote {
            in_single_quote = !in_single_quote;
            current.push(ch);
            continue;
        }

        if ch == '"' && !in_single_quote {
            in_double_quote = !in_double_quote;
            current.push(ch);
            continue;
        }

        // クォート内では分割しない
        if in_single_quote || in_double_quote {
            current.push(ch);
            continue;
        }

        // $(...) サブシェルの中身を検出するが、分割はしない
        // バッククォートも同様
        if ch == '$' && chars.peek() == Some(&'(') {
            current.push(ch);
            // サブシェルの中身をそのまま追加（ネスト対応）
            let subshell = consume_subshell(&mut chars);
            current.push_str(&subshell);
            continue;
        }

        if ch == '`' {
            current.push(ch);
            // バッククォート内をそのまま追加
            for inner in chars.by_ref() {
                current.push(inner);
                if inner == '`' {
                    break;
                }
            }
            continue;
        }

        // セパレータ: |, &&, ||, ;
        if ch == '|' {
            if chars.peek() == Some(&'|') {
                chars.next(); // || を消費
            }
            push_segment(&mut segments, &current);
            current.clear();
            continue;
        }

        if ch == '&' {
            if chars.peek() == Some(&'&') {
                chars.next(); // && を消費
                push_segment(&mut segments, &current);
                current.clear();
                continue;
            }
            // 単独の & (バックグラウンド) もセパレータ扱い
            push_segment(&mut segments, &current);
            current.clear();
            continue;
        }

        if ch == ';' {
            push_segment(&mut segments, &current);
            current.clear();
            continue;
        }

        current.push(ch);
    }

    push_segment(&mut segments, &current);
    segments
}

/// $(...) サブシェルを消費して文字列として返す（開き括弧から）
/// クォート内の `(` `)` は深さカウントに影響しない。
fn consume_subshell(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> String {
    let mut result = String::new();
    let mut depth = 0;
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escape_next = false;

    for ch in chars.by_ref() {
        result.push(ch);

        if escape_next {
            escape_next = false;
            continue;
        }

        if ch == '\\' && !in_single_quote {
            escape_next = true;
            continue;
        }

        if ch == '\'' && !in_double_quote {
            in_single_quote = !in_single_quote;
            continue;
        }

        if ch == '"' && !in_single_quote {
            in_double_quote = !in_double_quote;
            continue;
        }

        if in_single_quote || in_double_quote {
            continue;
        }

        if ch == '(' {
            depth += 1;
        } else if ch == ')' {
            depth -= 1;
            if depth == 0 {
                break;
            }
        }
    }
    result
}

fn push_segment(segments: &mut Vec<String>, segment: &str) {
    let trimmed = segment.trim();
    if !trimmed.is_empty() {
        segments.push(trimmed.to_string());
    }
}

/// シェル間接実行 (eval, bash -c, sh -c, xargs docker) を検出する。
/// docker コマンドが間接的に実行されようとしている場合 true を返す。
pub fn detect_shell_wrappers(segment: &str) -> bool {
    let trimmed = segment.trim();
    let cmd_part = skip_env_assignments(trimmed);

    // eval "...docker..."
    if let Some(rest) = cmd_part.strip_prefix("eval ")
        && contains_docker_keyword(rest)
    {
        return true;
    }

    // bash -c "...docker..." / sh -c "...docker..."
    // また bash/sh の後にオプションが来る場合にも対応
    if is_shell_dash_c_with_docker(cmd_part) {
        return true;
    }

    // sudo 経由のシェルラッパー
    let after_sudo = cmd_part
        .strip_prefix("sudo ")
        .or_else(|| cmd_part.strip_prefix("sudo\t"))
        .map(|s| s.trim_start());
    if let Some(inner) = after_sudo {
        if let Some(rest) = inner.strip_prefix("eval ")
            && contains_docker_keyword(rest)
        {
            return true;
        }
        if is_shell_dash_c_with_docker(inner) {
            return true;
        }
    }

    // xargs docker ...
    if cmd_part.starts_with("xargs ") || cmd_part.starts_with("xargs\t") {
        let rest = cmd_part.trim_start_matches("xargs").trim_start();
        // xargs の後のオプション (-0, -I{} 等) をスキップして docker を探す
        if contains_docker_keyword(rest) {
            return true;
        }
    }

    // 変数代入パターン: cmd="docker ..."; $cmd
    // → cmd_part に変数展開 ($) + docker が含まれる場合は検出不能だが、
    //   代入自体に docker が含まれるテキストがある場合を検出
    // (これは split_commands 後のセグメント単体では困難なので、
    //  process_command レベルで対処)

    false
}

/// コマンド文字列（クォート込み）に "docker" キーワードが含まれるかチェック
fn contains_docker_keyword(s: &str) -> bool {
    // クォートを除去した実質的な内容に docker が含まれるか
    s.contains("docker")
}

/// bash -c "...docker..." / sh -c '...docker...' パターンを検出
fn is_shell_dash_c_with_docker(cmd: &str) -> bool {
    // bash / sh / zsh を検出
    let shell_cmd = if cmd.starts_with("bash ") || cmd.starts_with("bash\t") {
        Some(cmd.strip_prefix("bash").unwrap().trim_start())
    } else if cmd.starts_with("sh ") || cmd.starts_with("sh\t") {
        Some(cmd.strip_prefix("sh").unwrap().trim_start())
    } else if cmd.starts_with("zsh ") || cmd.starts_with("zsh\t") {
        Some(cmd.strip_prefix("zsh").unwrap().trim_start())
    } else {
        // /bin/bash, /bin/sh, /usr/bin/env bash 等にも対応
        let prefixes = [
            "/bin/bash ", "/bin/sh ", "/usr/bin/bash ", "/usr/bin/sh ",
            "/bin/bash\t", "/bin/sh\t", "/usr/bin/bash\t", "/usr/bin/sh\t",
        ];
        prefixes.iter().find_map(|prefix| {
            cmd.strip_prefix(prefix).map(|rest| rest.trim_start())
        })
    };

    if let Some(args) = shell_cmd {
        // -c フラグを探す
        if args.starts_with("-c ") || args.starts_with("-c\t") {
            let rest = args.strip_prefix("-c").unwrap().trim_start();
            return contains_docker_keyword(rest);
        }
        // -c が他のオプションと組み合わさっている場合 (-xc 等)
        // 簡易的にフラグ群の後の -c を探す
        let parts: Vec<&str> = args.splitn(3, ' ').collect();
        if parts.len() >= 2 {
            for (idx, part) in parts.iter().enumerate() {
                if *part == "-c" {
                    let rest = parts[idx + 1..].join(" ");
                    return contains_docker_keyword(&rest);
                }
            }
        }
    }

    false
}

/// コマンドセグメントが docker コマンドで始まるか判定
pub fn is_docker_command(segment: &str) -> bool {
    let trimmed = segment.trim();
    // 先頭の環境変数設定 (FOO=bar) をスキップ
    let cmd_part = skip_env_assignments(trimmed);

    cmd_part == "docker"
        || cmd_part.starts_with("docker ")
        || cmd_part.starts_with("docker\t")
        || cmd_part == "docker-compose"
        || cmd_part.starts_with("docker-compose ")
        || cmd_part.starts_with("docker-compose\t")
        // sudo docker
        || cmd_part.starts_with("sudo docker")
        || cmd_part.starts_with("sudo docker-compose")
}

/// 先頭の環境変数設定 (FOO=bar) をスキップして、実際のコマンド部分を返す
fn skip_env_assignments(cmd: &str) -> &str {
    let mut rest = cmd;
    loop {
        let trimmed = rest.trim_start();
        // 環境変数パターン: NAME=VALUE の後にスペース
        if let Some(eq_pos) = trimmed.find('=') {
            let before_eq = &trimmed[..eq_pos];
            // = の前が有効な変数名（英数字とアンダースコア）であること
            if !before_eq.is_empty()
                && before_eq
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
                && before_eq.chars().next().is_some_and(|c| !c.is_ascii_digit())
            {
                // = の後の値を読み飛ばす（クォート対応）
                let after_eq = &trimmed[eq_pos + 1..];
                let value_end = find_value_end(after_eq);
                let remaining = &after_eq[value_end..];
                if remaining.is_empty() {
                    return trimmed; // 環境変数設定のみ
                }
                rest = remaining;
                continue;
            }
        }
        return trimmed;
    }
}

/// 環境変数の値の終端を見つける
fn find_value_end(s: &str) -> usize {
    let mut i = 0;
    let bytes = s.as_bytes();

    if i < bytes.len() && bytes[i] == b'\'' {
        // シングルクォート
        i += 1;
        while i < bytes.len() && bytes[i] != b'\'' {
            i += 1;
        }
        if i < bytes.len() {
            i += 1;
        }
    } else if i < bytes.len() && bytes[i] == b'"' {
        // ダブルクォート
        i += 1;
        while i < bytes.len() && bytes[i] != b'"' {
            if bytes[i] == b'\\' {
                i += 1;
            }
            i += 1;
        }
        if i < bytes.len() {
            i += 1;
        }
    } else {
        // クォートなし
        while i < bytes.len() && bytes[i] != b' ' && bytes[i] != b'\t' {
            i += 1;
        }
    }

    // 後続のスペースを飛ばす
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }

    i
}

/// コマンドセグメントから docker 引数部分を抽出する
/// (環境変数や sudo を除去して docker 以降の引数を返す)
pub fn extract_docker_args(segment: &str) -> Vec<String> {
    let cmd_part = skip_env_assignments(segment.trim());

    // sudo を除去
    let docker_part = if let Some(rest) = cmd_part.strip_prefix("sudo ") {
        rest.trim_start()
    } else if let Some(rest) = cmd_part.strip_prefix("sudo\t") {
        rest.trim_start()
    } else {
        cmd_part
    };

    // "docker" プレフィックスを除去
    let args_part = if let Some(rest) = docker_part.strip_prefix("docker-compose") {
        // docker-compose → compose として扱う
        let rest = rest.trim_start();
        format!("compose {}", rest)
    } else if let Some(rest) = docker_part.strip_prefix("docker") {
        rest.trim_start().to_string()
    } else {
        return Vec::new();
    };

    // shell-words でシェル引数分割
    match shell_words::split(&args_part) {
        Ok(args) => args,
        Err(_) => {
            // パースエラー時は最低限のスペース分割
            args_part.split_whitespace().map(String::from).collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_simple_pipe() {
        let result = split_commands("echo hello | grep world");
        assert_eq!(result, vec!["echo hello", "grep world"]);
    }

    #[test]
    fn test_split_chain() {
        let result = split_commands("cd /tmp && docker run ubuntu");
        assert_eq!(result, vec!["cd /tmp", "docker run ubuntu"]);
    }

    #[test]
    fn test_split_semicolon() {
        let result = split_commands("echo hello; docker run ubuntu; echo done");
        assert_eq!(
            result,
            vec!["echo hello", "docker run ubuntu", "echo done"]
        );
    }

    #[test]
    fn test_split_or_chain() {
        let result = split_commands("docker run ubuntu || echo failed");
        assert_eq!(result, vec!["docker run ubuntu", "echo failed"]);
    }

    #[test]
    fn test_split_quoted_pipe() {
        let result = split_commands(r#"echo "hello | world" && docker run ubuntu"#);
        assert_eq!(
            result,
            vec![r#"echo "hello | world""#, "docker run ubuntu"]
        );
    }

    #[test]
    fn test_split_single_quoted() {
        let result = split_commands("echo 'a && b' ; docker run ubuntu");
        assert_eq!(result, vec!["echo 'a && b'", "docker run ubuntu"]);
    }

    #[test]
    fn test_split_subshell() {
        let result = split_commands("echo $(docker ps) && docker run ubuntu");
        assert_eq!(
            result,
            vec!["echo $(docker ps)", "docker run ubuntu"]
        );
    }

    #[test]
    fn test_is_docker_command() {
        assert!(is_docker_command("docker run ubuntu"));
        assert!(is_docker_command("docker compose up"));
        assert!(is_docker_command("docker-compose up"));
        assert!(is_docker_command("sudo docker run ubuntu"));
        assert!(is_docker_command("DOCKER_HOST=tcp://localhost:2375 docker ps"));
        assert!(!is_docker_command("echo hello"));
        assert!(!is_docker_command("ls -la"));
    }

    #[test]
    fn test_extract_docker_args() {
        let args = extract_docker_args("docker run -v /etc:/data ubuntu");
        assert_eq!(args, vec!["run", "-v", "/etc:/data", "ubuntu"]);
    }

    #[test]
    fn test_extract_docker_args_sudo() {
        let args = extract_docker_args("sudo docker run ubuntu");
        assert_eq!(args, vec!["run", "ubuntu"]);
    }

    #[test]
    fn test_extract_docker_args_env() {
        let args =
            extract_docker_args("DOCKER_HOST=tcp://localhost:2375 docker ps");
        assert_eq!(args, vec!["ps"]);
    }

    #[test]
    fn test_extract_docker_compose() {
        let args = extract_docker_args("docker-compose up -d");
        assert_eq!(args, vec!["compose", "up", "-d"]);
    }

    #[test]
    fn test_split_empty() {
        let result = split_commands("");
        assert!(result.is_empty());
    }

    #[test]
    fn test_split_single_command() {
        let result = split_commands("docker run ubuntu");
        assert_eq!(result, vec!["docker run ubuntu"]);
    }
}
