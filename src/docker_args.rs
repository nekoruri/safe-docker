use regex::Regex;
use std::sync::LazyLock;

/// Docker サブコマンド
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DockerSubcommand {
    Run,
    Create,
    Build,
    Cp,
    Exec,
    ComposeUp,
    ComposeRun,
    ComposeCreate,
    ComposeExec,
    Other(String),
}

impl std::fmt::Display for DockerSubcommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Run => write!(f, "run"),
            Self::Create => write!(f, "create"),
            Self::Build => write!(f, "build"),
            Self::Cp => write!(f, "cp"),
            Self::Exec => write!(f, "exec"),
            Self::ComposeUp => write!(f, "compose-up"),
            Self::ComposeRun => write!(f, "compose-run"),
            Self::ComposeCreate => write!(f, "compose-create"),
            Self::ComposeExec => write!(f, "compose-exec"),
            Self::Other(s) => write!(f, "{}", s),
        }
    }
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
    VolumesFrom(String),
    UsernsHost,
    CgroupnsHost,
    IpcHost,
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
            DangerousFlag::VolumesFrom(src) => write!(f, "--volumes-from={}", src),
            DangerousFlag::UsernsHost => write!(f, "--userns=host"),
            DangerousFlag::CgroupnsHost => write!(f, "--cgroupns=host"),
            DangerousFlag::IpcHost => write!(f, "--ipc=host"),
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
    /// docker cp や docker build でのホストパス
    pub host_paths: Vec<String>,
}

static MOUNT_TYPE_BIND_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|,)type=bind(?:,|$)").unwrap());

static MOUNT_SOURCE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|,)(?:source|src)=([^,]+)").unwrap());

static MOUNT_TARGET_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|,)(?:target|dst|destination)=([^,]+)").unwrap());

static MOUNT_READONLY_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|,)(?:readonly|ro)(?:=true)?(?:,|$)").unwrap());

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
        host_paths: Vec::new(),
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
            | "images" | "ps" | "logs" | "inspect" | "rm" | "rmi" | "network" | "volume"
            | "buildx" => {
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
        "exec" => DockerSubcommand::Exec,
        "buildx" => {
            i += 1; // "buildx" を消費
            if i < args.len() && args[i] == "build" {
                DockerSubcommand::Build
            } else {
                DockerSubcommand::Other(format!("buildx-{}", args.get(i).unwrap_or(&"unknown")))
            }
        }
        _ => DockerSubcommand::Other(args[i].to_string()),
    };

    i += 1;

    // docker cp のパース: docker cp [OPTIONS] SRC DEST
    // SRC/DEST は container:path または host_path
    if cmd.subcommand == DockerSubcommand::Cp {
        parse_cp_args(args, i, &mut cmd);
        return cmd;
    }

    // docker build のパース: docker build [OPTIONS] PATH
    if cmd.subcommand == DockerSubcommand::Build {
        parse_build_args(args, i, &mut cmd);
        return cmd;
    }

    // docker exec のパース: docker exec [OPTIONS] CONTAINER COMMAND
    if cmd.subcommand == DockerSubcommand::Exec {
        parse_exec_args(args, i, &mut cmd);
        return cmd;
    }

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

        // --volumes-from
        if arg == "--volumes-from" {
            if i + 1 < args.len() {
                cmd.dangerous_flags
                    .push(DangerousFlag::VolumesFrom(args[i + 1].to_string()));
                i += 2;
                continue;
            }
        } else if let Some(value) = arg.strip_prefix("--volumes-from=") {
            cmd.dangerous_flags
                .push(DangerousFlag::VolumesFrom(value.to_string()));
            i += 1;
            continue;
        }

        // --userns
        if arg == "--userns" {
            if i + 1 < args.len() && args[i + 1] == "host" {
                cmd.dangerous_flags.push(DangerousFlag::UsernsHost);
                i += 2;
                continue;
            }
        } else if arg == "--userns=host" {
            cmd.dangerous_flags.push(DangerousFlag::UsernsHost);
            i += 1;
            continue;
        }

        // --cgroupns
        if arg == "--cgroupns" {
            if i + 1 < args.len() && args[i + 1] == "host" {
                cmd.dangerous_flags.push(DangerousFlag::CgroupnsHost);
                i += 2;
                continue;
            }
        } else if arg == "--cgroupns=host" {
            cmd.dangerous_flags.push(DangerousFlag::CgroupnsHost);
            i += 1;
            continue;
        }

        // --ipc
        if arg == "--ipc" {
            if i + 1 < args.len() && args[i + 1] == "host" {
                cmd.dangerous_flags.push(DangerousFlag::IpcHost);
                i += 2;
                continue;
            }
        } else if arg == "--ipc=host" {
            cmd.dangerous_flags.push(DangerousFlag::IpcHost);
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

/// docker cp 引数をパース: docker cp [OPTIONS] SRC DEST
/// container:path はコンテナパス、それ以外はホストパス
fn parse_cp_args(args: &[&str], start: usize, cmd: &mut DockerCommand) {
    let mut i = start;
    let mut positional = Vec::new();

    while i < args.len() {
        let arg = args[i];
        // cp のオプション (-a, -L, --follow-link, -q)
        if arg.starts_with('-') {
            i += 1;
            continue;
        }
        positional.push(arg);
        i += 1;
    }

    // SRC と DEST がホストパスかコンテナパスかを判定
    for path in &positional {
        // container:path パターン (コロン含みだがドライブレターでない)
        if path.contains(':') && !path.starts_with('/') && !path.starts_with('.') {
            // コンテナパスなのでスキップ
            continue;
        }
        // ホストパス
        cmd.host_paths.push(path.to_string());
    }
}

/// docker build 引数をパース: docker build [OPTIONS] PATH
fn parse_build_args(args: &[&str], start: usize, cmd: &mut DockerCommand) {
    let mut i = start;

    while i < args.len() {
        let arg = args[i];

        // -- 以降はコンテキストパス
        if arg == "--" {
            if i + 1 < args.len() {
                cmd.host_paths.push(args[i + 1].to_string());
            }
            break;
        }

        // 値を取るフラグをスキップ
        if matches!(
            arg,
            "-f" | "--file"
                | "-t"
                | "--tag"
                | "--build-arg"
                | "--target"
                | "--platform"
                | "--label"
                | "--cache-from"
                | "--network"
                | "--progress"
                | "--secret"
                | "--ssh"
                | "--output"
                | "-o"
                | "--iidfile"
                | "--load"
                | "--push"
        ) {
            i += 2;
            continue;
        }
        if arg.starts_with("--file=")
            || arg.starts_with("-f=")
            || arg.starts_with("--tag=")
            || arg.starts_with("-t=")
            || arg.starts_with("--build-arg=")
            || arg.starts_with("--target=")
        {
            i += 1;
            continue;
        }

        // ブーリアンフラグ
        if arg.starts_with('-') {
            i += 1;
            continue;
        }

        // 最初の非フラグ引数 = コンテキストパス
        cmd.host_paths.push(arg.to_string());
        break;
    }
}

/// docker exec 引数をパース: docker exec [OPTIONS] CONTAINER COMMAND [ARG...]
fn parse_exec_args(args: &[&str], start: usize, cmd: &mut DockerCommand) {
    let mut i = start;

    while i < args.len() {
        let arg = args[i];

        // --privileged
        if arg == "--privileged" {
            cmd.dangerous_flags.push(DangerousFlag::Privileged);
            i += 1;
            continue;
        }

        // 値付きオプション (-e, --env, -u, --user, -w, --workdir)
        if matches!(arg, "-e" | "--env" | "-u" | "--user" | "-w" | "--workdir") {
            i += 2;
            continue;
        }

        // = 付きオプションをスキップ
        if arg.starts_with("--env=") || arg.starts_with("--user=") || arg.starts_with("--workdir=")
        {
            i += 1;
            continue;
        }

        // ブーリアンフラグ (-d, --detach, -i, --interactive, -t, --tty)
        if arg.starts_with('-') {
            i += 1;
            continue;
        }

        // 非フラグ引数 = コンテナ名 → 以降はコンテナ内コマンドなので終了
        break;
    }
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
                    if (args[i] == "-v" || args[i] == "--volume") && i + 1 < args.len() {
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
            | "--userns"
            | "--volumes-from"
            | "--runtime"
            | "--cgroup-parent"
            | "--cidfile"
            | "--mac-address"
            | "--network-alias"
            | "--storage-opt"
            | "--sysctl"
            | "--gpus"
            | "--attach"
            | "-a"
            | "--link"
            | "--volume-driver"
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
        let bm = parse_mount_flag("type=bind,source=/host/path,target=/container/path").unwrap();
        assert_eq!(bm.host_path, "/host/path");
        assert_eq!(bm.container_path, "/container/path");
        assert!(!bm.read_only);
    }

    #[test]
    fn test_parse_mount_readonly() {
        let bm = parse_mount_flag("type=bind,source=/host,target=/container,readonly").unwrap();
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
        assert!(cmd.dangerous_flags.contains(&DangerousFlag::Privileged));
        assert!(
            cmd.dangerous_flags
                .contains(&DangerousFlag::CapAdd("SYS_ADMIN".to_string()))
        );
        assert!(cmd.dangerous_flags.contains(&DangerousFlag::PidHost));
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
        let args = vec!["run", "--mount", "source=/etc,target=/data", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert_eq!(
            cmd.bind_mounts.len(),
            0,
            "mount without type=bind should be ignored"
        );
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
        let args = vec!["run", "-v", "/etc:/data", "-v", "~/src:/app", "ubuntu"];
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

    // --- A4: is_flag_with_value 漏れ修正テスト ---

    #[test]
    fn test_is_flag_with_value_attach() {
        assert!(is_flag_with_value("--attach"));
        assert!(is_flag_with_value("-a"));
    }

    #[test]
    fn test_is_flag_with_value_link() {
        assert!(is_flag_with_value("--link"));
    }

    #[test]
    fn test_is_flag_with_value_volume_driver() {
        assert!(is_flag_with_value("--volume-driver"));
    }

    #[test]
    fn test_parse_attach_does_not_eat_image() {
        let args = vec!["run", "-a", "stdout", "--privileged", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(
            cmd.dangerous_flags.contains(&DangerousFlag::Privileged),
            "--privileged should be detected after -a stdout"
        );
        assert_eq!(cmd.image, Some("ubuntu".to_string()));
    }

    #[test]
    fn test_parse_link_does_not_eat_image() {
        let args = vec!["run", "--link", "db:db", "--privileged", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(cmd.dangerous_flags.contains(&DangerousFlag::Privileged));
    }

    // --- A1: docker buildx build テスト ---

    #[test]
    fn test_parse_buildx_build() {
        let args = vec!["buildx", "build", "-t", "myapp", "."];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.subcommand, DockerSubcommand::Build);
        assert_eq!(cmd.host_paths, vec!["."]);
    }

    #[test]
    fn test_parse_buildx_build_with_platform() {
        let args = vec![
            "buildx",
            "build",
            "-t",
            "myapp",
            "--platform",
            "linux/amd64",
            "/etc",
        ];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.subcommand, DockerSubcommand::Build);
        assert_eq!(cmd.host_paths, vec!["/etc"]);
    }

    #[test]
    fn test_parse_buildx_non_build() {
        let args = vec!["buildx", "inspect"];
        let cmd = parse_docker_args(&args);
        assert!(matches!(cmd.subcommand, DockerSubcommand::Other(_)));
    }

    // --- A2: docker exec テスト ---

    #[test]
    fn test_parse_docker_exec_privileged() {
        let args = vec!["exec", "--privileged", "mycontainer", "bash"];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.subcommand, DockerSubcommand::Exec);
        assert!(cmd.dangerous_flags.contains(&DangerousFlag::Privileged));
    }

    #[test]
    fn test_parse_docker_exec_no_flags() {
        let args = vec!["exec", "mycontainer", "ls", "-la"];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.subcommand, DockerSubcommand::Exec);
        assert!(cmd.dangerous_flags.is_empty());
    }

    #[test]
    fn test_parse_docker_exec_with_env() {
        let args = vec![
            "exec",
            "-e",
            "FOO=bar",
            "--privileged",
            "mycontainer",
            "bash",
        ];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.subcommand, DockerSubcommand::Exec);
        assert!(cmd.dangerous_flags.contains(&DangerousFlag::Privileged));
    }

    #[test]
    fn test_parse_docker_exec_interactive_tty() {
        let args = vec!["exec", "-it", "mycontainer", "bash"];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.subcommand, DockerSubcommand::Exec);
        assert!(cmd.dangerous_flags.is_empty());
    }
}
