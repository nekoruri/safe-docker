//! `safe-docker setup` サブコマンド
//!
//! Wrapper モードのセットアップを自動化する。
//! シンボリックリンク `~/.local/bin/docker -> safe-docker` を作成し、
//! PATH の設定状況を確認する。

use std::path::{Path, PathBuf};

/// ターゲットディレクトリに存在する docker の状態
enum ExistingDocker {
    /// 存在しない
    NotExists,
    /// safe-docker への既存シンボリックリンク
    SymlinkToSelf,
    /// 他のターゲットへのシンボリックリンク
    SymlinkToOther(PathBuf),
    /// 通常ファイル（本物の docker バイナリの可能性）
    RegularFile,
}

/// デフォルトのターゲットディレクトリ
fn default_target_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("~"))
        .join(".local/bin")
}

/// 自分自身の実行パスを取得（canonicalize 済み）
fn self_exe() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::canonicalize(p).ok())
}

/// ターゲットディレクトリ内の docker の状態を確認
fn check_existing(target_dir: &Path) -> ExistingDocker {
    let docker_path = target_dir.join("docker");

    if !docker_path.exists() && docker_path.symlink_metadata().is_err() {
        return ExistingDocker::NotExists;
    }

    // シンボリックリンクかどうか確認
    match std::fs::symlink_metadata(&docker_path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            // リンク先を解決して自分自身か確認
            if let Ok(resolved) = std::fs::canonicalize(&docker_path) {
                if let Some(self_path) = self_exe()
                    && resolved == self_path
                {
                    return ExistingDocker::SymlinkToSelf;
                }
                return ExistingDocker::SymlinkToOther(resolved);
            }
            // リンク先が解決できない（壊れたリンク）
            ExistingDocker::SymlinkToOther(PathBuf::from("(broken symlink)"))
        }
        Ok(_) => ExistingDocker::RegularFile,
        Err(_) => ExistingDocker::NotExists,
    }
}

/// PATH 内でターゲットディレクトリの位置を確認
fn check_path_position(target_dir: &Path) -> PathCheckResult {
    let path_env = std::env::var("PATH").unwrap_or_default();
    let target_str = target_dir.to_string_lossy();

    let mut target_found = false;
    let mut other_docker: Option<PathBuf> = None;

    for dir in path_env.split(':') {
        if dir == target_str.as_ref() {
            target_found = true;
            break;
        }

        // ターゲットより前に別の docker がないか
        let candidate = Path::new(dir).join("docker");
        if candidate.exists() && other_docker.is_none() {
            other_docker = Some(candidate);
        }
    }

    if !target_found {
        PathCheckResult::NotInPath
    } else if let Some(other) = other_docker {
        PathCheckResult::ShadowedBy(other)
    } else {
        PathCheckResult::Ok
    }
}

enum PathCheckResult {
    Ok,
    NotInPath,
    ShadowedBy(PathBuf),
}

/// セットアップヘルプを表示
fn print_setup_help() {
    eprintln!("safe-docker setup - Set up wrapper mode");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("  safe-docker setup [OPTIONS]");
    eprintln!();
    eprintln!("Creates a symlink so that all 'docker' commands are transparently checked.");
    eprintln!();
    eprintln!("OPTIONS:");
    eprintln!("  --target DIR    Target directory for the symlink (default: ~/.local/bin)");
    eprintln!("  --force         Overwrite existing symlink to another target");
    eprintln!("  --help          Show this help message");
    eprintln!();
    eprintln!("EXAMPLES:");
    eprintln!("  safe-docker setup");
    eprintln!("  safe-docker setup --target ~/bin");
    eprintln!("  safe-docker setup --force");
}

/// `safe-docker setup` のメインエントリポイント
pub fn run(args: &[String]) -> i32 {
    // --help
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_setup_help();
        return 0;
    }

    let force = args.iter().any(|a| a == "--force");

    // --target DIR
    let target_dir = args
        .windows(2)
        .find(|w| w[0] == "--target")
        .map(|w| PathBuf::from(&w[1]))
        .unwrap_or_else(default_target_dir);

    let self_path = match self_exe() {
        Some(p) => p,
        None => {
            eprintln!("[safe-docker] ERROR: Could not determine own executable path.");
            return 1;
        }
    };

    eprintln!("[safe-docker] Setting up wrapper mode...");

    // ターゲットディレクトリの作成
    if !target_dir.exists() {
        eprintln!("[safe-docker] Creating directory: {}", target_dir.display());
        if let Err(e) = std::fs::create_dir_all(&target_dir) {
            eprintln!(
                "[safe-docker] ERROR: Failed to create {}: {}",
                target_dir.display(),
                e
            );
            return 1;
        }
    }

    let docker_path = target_dir.join("docker");

    // 既存ファイルの確認
    match check_existing(&target_dir) {
        ExistingDocker::SymlinkToSelf => {
            eprintln!(
                "[safe-docker] Already set up: {} -> {}",
                docker_path.display(),
                self_path.display()
            );
            // PATH チェックのみ実行して終了
            print_path_advice(&target_dir);
            print_real_docker_info();
            return 0;
        }
        ExistingDocker::SymlinkToOther(other) => {
            if force {
                eprintln!(
                    "[safe-docker] Replacing existing symlink (was -> {})",
                    other.display()
                );
                if let Err(e) = std::fs::remove_file(&docker_path) {
                    eprintln!(
                        "[safe-docker] ERROR: Failed to remove {}: {}",
                        docker_path.display(),
                        e
                    );
                    return 1;
                }
            } else {
                eprintln!(
                    "[safe-docker] ERROR: {} already exists as symlink to {}",
                    docker_path.display(),
                    other.display()
                );
                eprintln!("  Use --force to replace it.");
                return 1;
            }
        }
        ExistingDocker::RegularFile => {
            eprintln!(
                "[safe-docker] ERROR: {} is a regular file (possibly the real docker binary).",
                docker_path.display()
            );
            eprintln!("  Refusing to overwrite for safety. Move or rename it first.");
            return 1;
        }
        ExistingDocker::NotExists => {
            // OK, proceed
        }
    }

    // シンボリックリンクの作成
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        if let Err(e) = symlink(&self_path, &docker_path) {
            eprintln!(
                "[safe-docker] ERROR: Failed to create symlink {} -> {}: {}",
                docker_path.display(),
                self_path.display(),
                e
            );
            return 1;
        }
    }

    #[cfg(not(unix))]
    {
        eprintln!("[safe-docker] ERROR: Symlink creation is only supported on Unix systems.");
        return 1;
    }

    eprintln!(
        "[safe-docker] Created symlink: {} -> {}",
        docker_path.display(),
        self_path.display()
    );
    eprintln!("[safe-docker] Setup complete!");
    eprintln!();

    print_path_advice(&target_dir);
    print_real_docker_info();

    eprintln!("  Run 'safe-docker --check-config' to verify your configuration.");

    0
}

/// PATH の設定状況を確認してアドバイスを表示
fn print_path_advice(target_dir: &Path) {
    match check_path_position(target_dir) {
        PathCheckResult::Ok => {}
        PathCheckResult::NotInPath => {
            eprintln!(
                "[safe-docker] WARNING: {} is not in your PATH.",
                target_dir.display()
            );
            eprintln!("  Add the following to your shell profile (~/.bashrc, ~/.zshrc, etc.):");
            eprintln!("    export PATH=\"{}:$PATH\"", target_dir.display());
            eprintln!();
        }
        PathCheckResult::ShadowedBy(other) => {
            eprintln!(
                "[safe-docker] WARNING: Another 'docker' is found before {} in your PATH:",
                target_dir.display()
            );
            eprintln!("    {}", other.display());
            eprintln!(
                "  Move {} to the beginning of your PATH for safe-docker to take effect.",
                target_dir.display()
            );
            eprintln!();
        }
    }
}

/// 本物の docker バイナリの検出情報を表示
fn print_real_docker_info() {
    let config = crate::config::Config::default();
    match crate::wrapper::find_real_docker_detailed(&config) {
        Ok(res) => {
            eprintln!(
                "  Real docker binary: {} (via {})",
                res.path.display(),
                res.source
            );
        }
        Err(_) => {
            eprintln!("  WARNING: Real docker binary not found in PATH.");
            eprintln!(
                "  Set wrapper.docker_path in config.toml or SAFE_DOCKER_DOCKER_PATH env var."
            );
        }
    }
    eprintln!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_check_existing_not_exists() {
        let dir = TempDir::new().unwrap();
        assert!(matches!(
            check_existing(dir.path()),
            ExistingDocker::NotExists
        ));
    }

    #[test]
    fn test_check_existing_regular_file() {
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("docker"), "fake").unwrap();
        assert!(matches!(
            check_existing(dir.path()),
            ExistingDocker::RegularFile
        ));
    }

    #[cfg(unix)]
    #[test]
    fn test_check_existing_symlink_to_self() {
        let dir = TempDir::new().unwrap();
        let self_path = self_exe().unwrap();
        std::os::unix::fs::symlink(&self_path, dir.path().join("docker")).unwrap();
        assert!(matches!(
            check_existing(dir.path()),
            ExistingDocker::SymlinkToSelf
        ));
    }

    #[cfg(unix)]
    #[test]
    fn test_check_existing_symlink_to_other() {
        let dir = TempDir::new().unwrap();
        std::os::unix::fs::symlink("/bin/echo", dir.path().join("docker")).unwrap();
        assert!(matches!(
            check_existing(dir.path()),
            ExistingDocker::SymlinkToOther(_)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn test_setup_creates_symlink() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("bin");
        let args = vec![
            "setup".to_string(),
            "--target".to_string(),
            target.to_string_lossy().to_string(),
        ];
        let exit_code = run(&args);
        assert_eq!(exit_code, 0);
        assert!(
            target
                .join("docker")
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_setup_already_done() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("bin");
        std::fs::create_dir_all(&target).unwrap();
        let self_path = self_exe().unwrap();
        std::os::unix::fs::symlink(&self_path, target.join("docker")).unwrap();

        let args = vec![
            "setup".to_string(),
            "--target".to_string(),
            target.to_string_lossy().to_string(),
        ];
        let exit_code = run(&args);
        assert_eq!(exit_code, 0);
    }

    #[cfg(unix)]
    #[test]
    fn test_setup_refuses_regular_file() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("bin");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("docker"), "real docker").unwrap();

        let args = vec![
            "setup".to_string(),
            "--target".to_string(),
            target.to_string_lossy().to_string(),
        ];
        let exit_code = run(&args);
        assert_eq!(exit_code, 1); // 通常ファイルは上書き拒否
    }

    #[cfg(unix)]
    #[test]
    fn test_setup_force_replaces_other_symlink() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("bin");
        std::fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink("/bin/echo", target.join("docker")).unwrap();

        let args = vec![
            "setup".to_string(),
            "--target".to_string(),
            target.to_string_lossy().to_string(),
            "--force".to_string(),
        ];
        let exit_code = run(&args);
        assert_eq!(exit_code, 0);
        // 新しいリンク先が self であることを確認
        let resolved = std::fs::canonicalize(target.join("docker")).unwrap();
        assert_eq!(resolved, self_exe().unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn test_setup_no_force_rejects_other_symlink() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("bin");
        std::fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink("/bin/echo", target.join("docker")).unwrap();

        let args = vec![
            "setup".to_string(),
            "--target".to_string(),
            target.to_string_lossy().to_string(),
        ];
        let exit_code = run(&args);
        assert_eq!(exit_code, 1); // --force なしでは拒否
    }

    #[test]
    fn test_default_target_dir() {
        let target = default_target_dir();
        assert!(target.to_string_lossy().contains(".local/bin"));
    }
}
