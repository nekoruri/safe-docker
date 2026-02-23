use regex::Regex;
use std::sync::LazyLock;

/// Docker サブコマンド
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DockerSubcommand {
    Run,
    Create,
    Build,
    Cp,
    ComposeUp,
    ComposeRun,
    ComposeCreate,
    ComposeExec,
    Other(String),
}

/// バインドマウントの由来
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MountSource {
    VolumeFlag,     // -v / --volume
    MountFlag,      // --mount
    ComposeVolumes, // docker-compose.yml の volumes
}

/// バインドマウント情報
#[derive(Debug, Clone)]
pub struct BindMount {
    pub host_path: String,
    pub container_path: String,
    pub source: MountSource,
    pub read_only: bool,
}

/// 危険フラグ
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DangerousFlag {
    Privileged,
    CapAdd(String),
    SecurityOpt(String),
    PidHost,
    NetworkHost,
    Device(String),
}

impl std::fmt::Display for DangerousFlag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DangerousFlag::Privileged => write!(f, "--privileged"),
            DangerousFlag::CapAdd(cap) => write!(f, "--cap-add={}", cap),
            DangerousFlag::SecurityOpt(opt) => write!(f, "--security-opt {}", opt),
            DangerousFlag::PidHost => write!(f, "--pid=host"),
            DangerousFlag::NetworkHost => write!(f, "--network=host"),
            DangerousFlag::Device(dev) => write!(f, "--device={}", dev),
        }
    }
}

/// Docker コマンドのパース結果
#[derive(Debug, Clone)]
pub struct DockerCommand {
    pub subcommand: DockerSubcommand,
    pub bind_mounts: Vec<BindMount>,
    pub dangerous_flags: Vec<DangerousFlag>,
    pub compose_file: Option<String>,
    pub image: Option<String>,
}

static MOUNT_TYPE_BIND_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|,)type=bind(?:,|$)").unwrap()
});

static MOUNT_SOURCE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|,)(?:source|src)=([^,]+)").unwrap()
});

static MOUNT_TARGET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|,)(?:target|dst|destination)=([^,]+)").unwrap()
});

static MOUNT_READONLY_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|,)(?:readonly|ro)(?:=true)?(?:,|$)").unwrap()
});

/// -v / --volume フラグの値からバインドマウントをパースする
fn parse_volume_flag(value: &str) -> Option<BindMount> {
    // 名前付きボリュームはスキップ (ホストパスは / か . か ~ で始まる)
    // format: host_path:container_path[:opts]
    let parts: Vec<&str> = value.splitn(3, ':').collect();
    if parts.len() < 2 {
        return None;
    }

    let host = parts[0];
    // 名前付きボリュームかパスかを判別
    if !host.starts_with('/')
        && !host.starts_with('.')
        && !host.starts_with('~')
        && !host.starts_with('$')
    {
        return None; // 名前付きボリューム
    }

    let read_only = parts
        .get(2)
        .is_some_and(|opts| opts.split(',').any(|o| o == "ro"));

    Some(BindMount {
        host_path: host.to_string(),
        container_path: parts[1].to_string(),
        source: MountSource::VolumeFlag,
        read_only,
    })
}

/// --mount フラグの値からバインドマウントをパースする
fn parse_mount_flag(value: &str) -> Option<BindMount> {
    // type=bind のみ対象
    if !MOUNT_TYPE_BIND_RE.is_match(value) {
        return None;
    }

    let source = MOUNT_SOURCE_RE
        .captures(value)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())?;

    let target = MOUNT_TARGET_RE
        .captures(value)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();

    let read_only = MOUNT_READONLY_RE.is_match(value);

    Some(BindMount {
        host_path: source,
        container_path: target,
        source: MountSource::MountFlag,
        read_only,
    })
}

/// docker 引数をパースして DockerCommand を返す
pub fn parse_docker_args(args: &[&str]) -> DockerCommand {
    let mut cmd = DockerCommand {
        subcommand: DockerSubcommand::Other("unknown".to_string()),
        bind_mounts: Vec::new(),
        dangerous_flags: Vec::new(),
        compose_file: None,
        image: None,
    };

    if args.is_empty() {
        return cmd;
    }

    let mut i = 0;
    let mut found_subcommand = false;
    let mut is_compose = false;

    // docker compose の検出とグローバルオプションのスキップ
    while i < args.len() {
        let arg = args[i];
        match arg {
            "compose" | "docker-compose" => {
                is_compose = true;
                i += 1;
                break;
            }
            "run" | "create" | "build" | "cp" | "exec" | "start" | "stop" | "pull" | "push"
            | "images" | "ps" | "logs" | "inspect" | "rm" | "rmi" | "network" | "volume" => {
                found_subcommand = true;
                break;
            }
            _ => {
                // グローバルオプション (-H, --host 等) をスキップ
                i += 1;
            }
        }
    }

    if is_compose {
        parse_compose_args(args, i, &mut cmd);
        return cmd;
    }

    if !found_subcommand {
        return cmd;
    }

    // サブコマンドの判定
    cmd.subcommand = match args[i] {
        "run" => DockerSubcommand::Run,
        "create" => DockerSubcommand::Create,
        "build" => DockerSubcommand::Build,
        "cp" => DockerSubcommand::Cp,
        _ => DockerSubcommand::Other(args[i].to_string()),
    };

    i += 1;

    // run / create のフラグをパース
    let parse_flags = matches!(
        cmd.subcommand,
        DockerSubcommand::Run | DockerSubcommand::Create
    );

    if !parse_flags {
        return cmd;
    }

    while i < args.len() {
        let arg = args[i];

        // -- 以降はイメージ名 + コマンド
        if arg == "--" {
            if i + 1 < args.len() {
                cmd.image = Some(args[i + 1].to_string());
            }
            break;
        }

        // -v / --volume
        if (arg == "-v" || arg == "--volume") && i + 1 < args.len() {
            if let Some(bm) = parse_volume_flag(args[i + 1]) {
                cmd.bind_mounts.push(bm);
            }
            i += 2;
            continue;
        } else if let Some(value) = arg.strip_prefix("--volume=") {
            if let Some(bm) = parse_volume_flag(value) {
                cmd.bind_mounts.push(bm);
            }
            i += 1;
            continue;
        } else if let Some(value) = arg.strip_prefix("-v=") {
            if let Some(bm) = parse_volume_flag(value) {
                cmd.bind_mounts.push(bm);
            }
            i += 1;
            continue;
        }

        // --mount
        if arg == "--mount" {
            if i + 1 < args.len() {
                if let Some(bm) = parse_mount_flag(args[i + 1]) {
                    cmd.bind_mounts.push(bm);
                }
                i += 2;
                continue;
            }
        } else if let Some(value) = arg.strip_prefix("--mount=") {
            if let Some(bm) = parse_mount_flag(value) {
                cmd.bind_mounts.push(bm);
            }
            i += 1;
            continue;
        }

        // --privileged
        if arg == "--privileged" {
            cmd.dangerous_flags.push(DangerousFlag::Privileged);
            i += 1;
            continue;
        }

        // --cap-add
        if arg == "--cap-add" {
            if i + 1 < args.len() {
                cmd.dangerous_flags
                    .push(DangerousFlag::CapAdd(args[i + 1].to_string()));
                i += 2;
                continue;
            }
        } else if let Some(value) = arg.strip_prefix("--cap-add=") {
            cmd.dangerous_flags
                .push(DangerousFlag::CapAdd(value.to_string()));
            i += 1;
            continue;
        }

        // --security-opt
        if arg == "--security-opt" {
            if i + 1 < args.len() {
                cmd.dangerous_flags
                    .push(DangerousFlag::SecurityOpt(args[i + 1].to_string()));
                i += 2;
                continue;
            }
        } else if let Some(value) = arg.strip_prefix("--security-opt=") {
            cmd.dangerous_flags
                .push(DangerousFlag::SecurityOpt(value.to_string()));
            i += 1;
            continue;
        }

        // --pid
        if arg == "--pid" {
            if i + 1 < args.len() && args[i + 1] == "host" {
                cmd.dangerous_flags.push(DangerousFlag::PidHost);
                i += 2;
                continue;
            }
        } else if arg == "--pid=host" {
            cmd.dangerous_flags.push(DangerousFlag::PidHost);
            i += 1;
            continue;
        }

        // --network / --net
        if arg == "--network" || arg == "--net" {
            if i + 1 < args.len() && args[i + 1] == "host" {
                cmd.dangerous_flags.push(DangerousFlag::NetworkHost);
                i += 2;
                continue;
            }
        } else if arg == "--network=host" || arg == "--net=host" {
            cmd.dangerous_flags.push(DangerousFlag::NetworkHost);
            i += 1;
            continue;
        }

        // --device
        if arg == "--device" {
            if i + 1 < args.len() {
                cmd.dangerous_flags
                    .push(DangerousFlag::Device(args[i + 1].to_string()));
                i += 2;
                continue;
            }
        } else if let Some(value) = arg.strip_prefix("--device=") {
            cmd.dangerous_flags
                .push(DangerousFlag::Device(value.to_string()));
            i += 1;
            continue;
        }

        // 値付きオプションのスキップ (-e, --env, --name, -w, --workdir, etc.)
        if is_flag_with_value(arg) {
            i += 2;
            continue;
        }

        // フラグでない引数 → イメージ名 (最初の非フラグ引数)
        if !arg.starts_with('-') && cmd.image.is_none() {
            cmd.image = Some(arg.to_string());
            // 以降はコンテナ内コマンドなので終了
            break;
        }

        i += 1;
    }

    cmd
}

/// docker compose 引数をパース
fn parse_compose_args(args: &[&str], start: usize, cmd: &mut DockerCommand) {
    let mut i = start;

    // compose のグローバルオプション (-f 等) を処理
    while i < args.len() {
        let arg = args[i];
        if arg == "-f" || arg == "--file" {
            if i + 1 < args.len() {
                cmd.compose_file = Some(args[i + 1].to_string());
                i += 2;
                continue;
            }
        } else if let Some(value) = arg.strip_prefix("--file=") {
            cmd.compose_file = Some(value.to_string());
            i += 1;
            continue;
        }

        // compose サブコマンド
        match arg {
            "up" => {
                cmd.subcommand = DockerSubcommand::ComposeUp;
                break;
            }
            "run" => {
                cmd.subcommand = DockerSubcommand::ComposeRun;
                i += 1;
                // compose run のフラグから -v を抽出
                while i < args.len() {
                    if (args[i] == "-v" || args[i] == "--volume")
                        && i + 1 < args.len()
                    {
                        if let Some(bm) = parse_volume_flag(args[i + 1]) {
                            cmd.bind_mounts.push(bm);
                        }
                        i += 2;
                        continue;
                    }
                    i += 1;
                }
                return;
            }
            "create" => {
                cmd.subcommand = DockerSubcommand::ComposeCreate;
                break;
            }
            "exec" => {
                cmd.subcommand = DockerSubcommand::ComposeExec;
                break;
            }
            _ => {
                i += 1;
            }
        }
    }
}

/// 値を取るフラグかどうか判定 (次の引数をスキップするため)
fn is_flag_with_value(arg: &str) -> bool {
    matches!(
        arg,
        "-e" | "--env"
            | "--name"
            | "-w"
            | "--workdir"
            | "-p"
            | "--publish"
            | "--expose"
            | "-l"
            | "--label"
            | "--hostname"
            | "-h"
            | "--user"
            | "-u"
            | "--entrypoint"
            | "--restart"
            | "--memory"
            | "-m"
            | "--cpus"
            | "--log-driver"
            | "--log-opt"
            | "--network"
            | "--net"
            | "--ip"
            | "--dns"
            | "--add-host"
            | "--tmpfs"
            | "--shm-size"
            | "--ulimit"
            | "--stop-signal"
            | "--stop-timeout"
            | "--health-cmd"
            | "--health-interval"
            | "--health-retries"
            | "--health-start-period"
            | "--health-timeout"
            | "--platform"
            | "--pull"
            | "--cgroupns"
            | "--ipc"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_volume_short() {
        let bm = parse_volume_flag("/host/path:/container/path").unwrap();
        assert_eq!(bm.host_path, "/host/path");
        assert_eq!(bm.container_path, "/container/path");
        assert!(!bm.read_only);
    }

    #[test]
    fn test_parse_volume_readonly() {
        let bm = parse_volume_flag("/host:/container:ro").unwrap();
        assert!(bm.read_only);
    }

    #[test]
    fn test_parse_volume_named() {
        assert!(parse_volume_flag("myvolume:/container").is_none());
    }

    #[test]
    fn test_parse_volume_home() {
        let bm = parse_volume_flag("~/projects:/app").unwrap();
        assert_eq!(bm.host_path, "~/projects");
    }

    #[test]
    fn test_parse_volume_relative() {
        let bm = parse_volume_flag("./src:/app/src").unwrap();
        assert_eq!(bm.host_path, "./src");
    }

    #[test]
    fn test_parse_mount_bind() {
        let bm =
            parse_mount_flag("type=bind,source=/host/path,target=/container/path").unwrap();
        assert_eq!(bm.host_path, "/host/path");
        assert_eq!(bm.container_path, "/container/path");
        assert!(!bm.read_only);
    }

    #[test]
    fn test_parse_mount_readonly() {
        let bm =
            parse_mount_flag("type=bind,source=/host,target=/container,readonly").unwrap();
        assert!(bm.read_only);
    }

    #[test]
    fn test_parse_mount_volume_type() {
        assert!(parse_mount_flag("type=volume,source=myvol,target=/data").is_none());
    }

    #[test]
    fn test_parse_mount_src_dst() {
        let bm = parse_mount_flag("type=bind,src=/host,dst=/container").unwrap();
        assert_eq!(bm.host_path, "/host");
        assert_eq!(bm.container_path, "/container");
    }

    #[test]
    fn test_parse_docker_run_basic() {
        let args = vec!["run", "-v", "/etc:/data", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.subcommand, DockerSubcommand::Run);
        assert_eq!(cmd.bind_mounts.len(), 1);
        assert_eq!(cmd.bind_mounts[0].host_path, "/etc");
        assert_eq!(cmd.image, Some("ubuntu".to_string()));
    }

    #[test]
    fn test_parse_docker_run_multiple_volumes() {
        let args = vec![
            "run",
            "-v",
            "/home/user/src:/app",
            "-v",
            "/etc/config:/config:ro",
            "--name",
            "test",
            "alpine",
        ];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.bind_mounts.len(), 2);
    }

    #[test]
    fn test_parse_docker_run_mount_flag() {
        let args = vec![
            "run",
            "--mount",
            "type=bind,source=/host,target=/container",
            "ubuntu",
        ];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.bind_mounts.len(), 1);
        assert_eq!(cmd.bind_mounts[0].host_path, "/host");
    }

    #[test]
    fn test_parse_dangerous_flags() {
        let args = vec![
            "run",
            "--privileged",
            "--cap-add",
            "SYS_ADMIN",
            "--security-opt",
            "apparmor=unconfined",
            "--pid=host",
            "ubuntu",
        ];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.dangerous_flags.len(), 4);
        assert!(cmd
            .dangerous_flags
            .contains(&DangerousFlag::Privileged));
        assert!(cmd
            .dangerous_flags
            .contains(&DangerousFlag::CapAdd("SYS_ADMIN".to_string())));
        assert!(cmd
            .dangerous_flags
            .contains(&DangerousFlag::PidHost));
    }

    #[test]
    fn test_parse_compose_up() {
        let args = vec!["compose", "-f", "custom.yml", "up"];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.subcommand, DockerSubcommand::ComposeUp);
        assert_eq!(cmd.compose_file, Some("custom.yml".to_string()));
    }

    #[test]
    fn test_parse_compose_run_with_volume() {
        let args = vec!["compose", "run", "-v", "/etc:/data", "web"];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.subcommand, DockerSubcommand::ComposeRun);
        assert_eq!(cmd.bind_mounts.len(), 1);
    }

    #[test]
    fn test_parse_no_subcommand() {
        let args = vec!["--version"];
        let cmd = parse_docker_args(&args);
        assert!(matches!(cmd.subcommand, DockerSubcommand::Other(_)));
    }

    #[test]
    fn test_parse_volume_equals_syntax() {
        let args = vec!["run", "--volume=/etc:/data", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.bind_mounts.len(), 1);
        assert_eq!(cmd.bind_mounts[0].host_path, "/etc");
    }

    #[test]
    fn test_parse_device_flag() {
        let args = vec!["run", "--device", "/dev/sda", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(matches!(
            &cmd.dangerous_flags[0],
            DangerousFlag::Device(d) if d == "/dev/sda"
        ));
    }

    // --- エッジケーステスト ---

    #[test]
    fn test_parse_docker_create() {
        let args = vec!["create", "-v", "/etc:/data", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.subcommand, DockerSubcommand::Create);
        assert_eq!(cmd.bind_mounts.len(), 1);
        assert_eq!(cmd.bind_mounts[0].host_path, "/etc");
    }

    #[test]
    fn test_parse_docker_run_double_dash() {
        let args = vec!["run", "--", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.subcommand, DockerSubcommand::Run);
        assert_eq!(cmd.image, Some("ubuntu".to_string()));
    }

    #[test]
    fn test_parse_empty_volume() {
        // 空の volume 値は無視される
        let args = vec!["run", "-v", "", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.bind_mounts.len(), 0);
    }

    #[test]
    fn test_parse_volume_equals_empty() {
        // --volume= (空) は無視される
        let args = vec!["run", "--volume=", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.bind_mounts.len(), 0);
    }

    #[test]
    fn test_parse_mount_no_type() {
        // type 指定なしの --mount は volume として無視
        let args = vec![
            "run",
            "--mount",
            "source=/etc,target=/data",
            "ubuntu",
        ];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.bind_mounts.len(), 0, "mount without type=bind should be ignored");
    }

    #[test]
    fn test_parse_cap_add_equals_syntax() {
        let args = vec!["run", "--cap-add=SYS_ADMIN", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.dangerous_flags.len(), 1);
        assert!(matches!(
            &cmd.dangerous_flags[0],
            DangerousFlag::CapAdd(c) if c == "SYS_ADMIN"
        ));
    }

    #[test]
    fn test_parse_security_opt_equals_syntax() {
        let args = vec!["run", "--security-opt=apparmor=unconfined", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.dangerous_flags.len(), 1);
        assert!(matches!(
            &cmd.dangerous_flags[0],
            DangerousFlag::SecurityOpt(s) if s == "apparmor=unconfined"
        ));
    }

    #[test]
    fn test_parse_device_equals_syntax() {
        let args = vec!["run", "--device=/dev/fuse", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.dangerous_flags.len(), 1);
        assert!(matches!(
            &cmd.dangerous_flags[0],
            DangerousFlag::Device(d) if d == "/dev/fuse"
        ));
    }

    #[test]
    fn test_parse_mixed_volumes_deny_priority() {
        let args = vec![
            "run",
            "-v", "/etc:/data",
            "-v", "~/src:/app",
            "ubuntu",
        ];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.bind_mounts.len(), 2);
        // 最初が /etc (deny対象)、次が ~/src
        assert_eq!(cmd.bind_mounts[0].host_path, "/etc");
        assert_eq!(cmd.bind_mounts[1].host_path, "~/src");
    }

    #[test]
    fn test_parse_empty_args() {
        let args: Vec<&str> = vec![];
        let cmd = parse_docker_args(&args);
        assert!(matches!(cmd.subcommand, DockerSubcommand::Other(_)));
    }

    #[test]
    fn test_parse_net_host_space() {
        let args = vec!["run", "--net", "host", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(
            cmd.dangerous_flags.contains(&DangerousFlag::NetworkHost),
            "--net host (space-separated) should be detected"
        );
    }

    #[test]
    fn test_parse_network_host_equals() {
        let args = vec!["run", "--network=host", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(cmd.dangerous_flags.contains(&DangerousFlag::NetworkHost));
    }

    #[test]
    fn test_parse_compose_exec() {
        let args = vec!["compose", "exec", "web", "bash"];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.subcommand, DockerSubcommand::ComposeExec);
    }

    #[test]
    fn test_parse_compose_file_equals() {
        let args = vec!["compose", "--file=custom.yml", "up"];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.compose_file, Some("custom.yml".to_string()));
        assert_eq!(cmd.subcommand, DockerSubcommand::ComposeUp);
    }

    #[test]
    fn test_parse_mount_equals_syntax() {
        let args = vec![
            "run",
            "--mount=type=bind,source=/etc,target=/data",
            "ubuntu",
        ];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.bind_mounts.len(), 1);
        assert_eq!(cmd.bind_mounts[0].host_path, "/etc");
    }

    #[test]
    fn test_parse_v_equals_syntax() {
        let args = vec!["run", "-v=/etc:/data", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.bind_mounts.len(), 1);
        assert_eq!(cmd.bind_mounts[0].host_path, "/etc");
    }

    #[test]
    fn test_parse_pid_host_space() {
        let args = vec!["run", "--pid", "host", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(cmd.dangerous_flags.contains(&DangerousFlag::PidHost));
    }
}
