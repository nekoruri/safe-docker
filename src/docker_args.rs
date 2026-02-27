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
    /// --uts=host (ホスト UTS 名前空間の共有)
    UtsHost,
    /// --network=container:NAME (コンテナ間ネットワーク共有)
    NetworkContainer(String),
    /// --pid=container:NAME (コンテナ間プロセス名前空間共有)
    PidContainer(String),
    /// --ipc=container:NAME (コンテナ間IPC名前空間共有)
    IpcContainer(String),
    /// --mount bind-propagation=shared/rshared (マウント伝搬)
    MountPropagation(String),
    /// --sysctl KEY=VALUE (カーネルパラメータ設定)
    Sysctl(String),
    /// --add-host HOST:IP (ホスト名解決エントリ)
    AddHost(String),
    /// --build-arg KEY=VALUE where KEY looks like a secret
    BuildArgSecret(String),
    /// --cgroup-parent VALUE (カスタム cgroup 親の指定)
    CgroupParent(String),
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
            DangerousFlag::UtsHost => write!(f, "--uts=host"),
            DangerousFlag::NetworkContainer(name) => {
                write!(f, "--network=container:{}", name)
            }
            DangerousFlag::PidContainer(name) => write!(f, "--pid=container:{}", name),
            DangerousFlag::IpcContainer(name) => write!(f, "--ipc=container:{}", name),
            DangerousFlag::MountPropagation(mode) => {
                write!(f, "bind-propagation={}", mode)
            }
            DangerousFlag::Sysctl(val) => write!(f, "--sysctl {}", val),
            DangerousFlag::AddHost(val) => write!(f, "--add-host {}", val),
            DangerousFlag::BuildArgSecret(val) => write!(f, "--build-arg {}", val),
            DangerousFlag::CgroupParent(val) => write!(f, "--cgroup-parent={}", val),
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

static MOUNT_PROPAGATION_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|,)bind-propagation=(shared|rshared|slave|rslave|private|rprivate)(?:,|$)")
        .unwrap()
});

/// -v / --volume フラグの値からバインドマウントをパースする
/// propagation が検出された場合は dangerous_flags に追加
fn parse_volume_flag(value: &str, dangerous_flags: &mut Vec<DangerousFlag>) -> Option<BindMount> {
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

    let opts = parts.get(2).copied().unwrap_or("");
    let read_only = opts.split(',').any(|o| o == "ro");

    // propagation の検出 (shared, rshared)
    for opt in opts.split(',') {
        if matches!(opt, "shared" | "rshared") {
            dangerous_flags.push(DangerousFlag::MountPropagation(opt.to_string()));
        }
    }

    Some(BindMount {
        host_path: host.to_string(),
        container_path: parts[1].to_string(),
        source: MountSource::VolumeFlag,
        read_only,
    })
}

/// --mount フラグの値からバインドマウントをパースする
/// propagation が検出された場合は dangerous_flags に追加
fn parse_mount_flag(value: &str, dangerous_flags: &mut Vec<DangerousFlag>) -> Option<BindMount> {
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

    // bind-propagation の検出
    if let Some(caps) = MOUNT_PROPAGATION_RE.captures(value) {
        let mode = caps.get(1).unwrap().as_str();
        if matches!(mode, "shared" | "rshared") {
            dangerous_flags.push(DangerousFlag::MountPropagation(mode.to_string()));
        }
    }

    Some(BindMount {
        host_path: source,
        container_path: target,
        source: MountSource::MountFlag,
        read_only,
    })
}

/// --security-opt seccomp=PATH からパスを抽出してホストパス検証対象に追加する
/// seccomp=unconfined は DangerousFlag で処理済みなのでスキップ
fn extract_seccomp_path(opt: &str, host_paths: &mut Vec<String>) {
    // seccomp= または seccomp: のどちらの形式にも対応
    let path = opt
        .strip_prefix("seccomp=")
        .or_else(|| opt.strip_prefix("seccomp:"));
    if let Some(path) = path
        && path != "unconfined"
        && !path.is_empty()
    {
        host_paths.push(path.to_string());
    }
}

/// --build-arg の KEY 名が機密情報を含むパターンかどうか判定
fn is_secret_build_arg(arg: &str) -> bool {
    // KEY=VALUE の KEY 部分を取り出す (VALUE がない場合は arg 全体が KEY)
    let key = arg.split('=').next().unwrap_or(arg);
    let key_upper = key.to_uppercase();
    key_upper.contains("SECRET")
        || key_upper.contains("PASSWORD")
        || key_upper.contains("PASSWD")
        || key_upper.contains("TOKEN")
        || key_upper.contains("PRIVATE_KEY")
        || key_upper.contains("API_KEY")
        || key_upper.contains("APIKEY")
        || key_upper.contains("CREDENTIAL")
        || key_upper.ends_with("_KEY")
        || key_upper.contains("_KEY_")
        || key_upper == "KEY"
}

/// --secret / --ssh のカンマ区切りオプションからソースパスを抽出
fn extract_build_secret_path(opt: &str) -> Option<String> {
    for part in opt.split(',') {
        if let Some(path) = part
            .strip_prefix("src=")
            .or_else(|| part.strip_prefix("source="))
            && !path.is_empty()
        {
            return Some(path.to_string());
        }
    }
    None
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
            if let Some(bm) = parse_volume_flag(args[i + 1], &mut cmd.dangerous_flags) {
                cmd.bind_mounts.push(bm);
            }
            i += 2;
            continue;
        } else if let Some(value) = arg.strip_prefix("--volume=") {
            if let Some(bm) = parse_volume_flag(value, &mut cmd.dangerous_flags) {
                cmd.bind_mounts.push(bm);
            }
            i += 1;
            continue;
        } else if let Some(value) = arg.strip_prefix("-v=") {
            if let Some(bm) = parse_volume_flag(value, &mut cmd.dangerous_flags) {
                cmd.bind_mounts.push(bm);
            }
            i += 1;
            continue;
        }

        // --mount
        if arg == "--mount" {
            if i + 1 < args.len() {
                if let Some(bm) = parse_mount_flag(args[i + 1], &mut cmd.dangerous_flags) {
                    cmd.bind_mounts.push(bm);
                }
                i += 2;
                continue;
            }
        } else if let Some(value) = arg.strip_prefix("--mount=") {
            if let Some(bm) = parse_mount_flag(value, &mut cmd.dangerous_flags) {
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
                let opt_value = args[i + 1];
                cmd.dangerous_flags
                    .push(DangerousFlag::SecurityOpt(opt_value.to_string()));
                // seccomp=PATH (unconfined 以外のパスを検証)
                extract_seccomp_path(opt_value, &mut cmd.host_paths);
                i += 2;
                continue;
            }
        } else if let Some(value) = arg.strip_prefix("--security-opt=") {
            cmd.dangerous_flags
                .push(DangerousFlag::SecurityOpt(value.to_string()));
            extract_seccomp_path(value, &mut cmd.host_paths);
            i += 1;
            continue;
        }

        // --pid
        if arg == "--pid" {
            if i + 1 < args.len() {
                let val = args[i + 1];
                if val == "host" {
                    cmd.dangerous_flags.push(DangerousFlag::PidHost);
                } else if let Some(name) = val.strip_prefix("container:") {
                    cmd.dangerous_flags
                        .push(DangerousFlag::PidContainer(name.to_string()));
                }
                i += 2;
                continue;
            }
        } else if let Some(val) = arg.strip_prefix("--pid=") {
            if val == "host" {
                cmd.dangerous_flags.push(DangerousFlag::PidHost);
            } else if let Some(name) = val.strip_prefix("container:") {
                cmd.dangerous_flags
                    .push(DangerousFlag::PidContainer(name.to_string()));
            }
            i += 1;
            continue;
        }

        // --network / --net
        if arg == "--network" || arg == "--net" {
            if i + 1 < args.len() {
                let val = args[i + 1];
                if val == "host" {
                    cmd.dangerous_flags.push(DangerousFlag::NetworkHost);
                } else if let Some(name) = val.strip_prefix("container:") {
                    cmd.dangerous_flags
                        .push(DangerousFlag::NetworkContainer(name.to_string()));
                }
                i += 2;
                continue;
            }
        } else if let Some(val) = arg
            .strip_prefix("--network=")
            .or_else(|| arg.strip_prefix("--net="))
        {
            if val == "host" {
                cmd.dangerous_flags.push(DangerousFlag::NetworkHost);
            } else if let Some(name) = val.strip_prefix("container:") {
                cmd.dangerous_flags
                    .push(DangerousFlag::NetworkContainer(name.to_string()));
            }
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

        // --cgroup-parent
        if arg == "--cgroup-parent" {
            if i + 1 < args.len() {
                cmd.dangerous_flags
                    .push(DangerousFlag::CgroupParent(args[i + 1].to_string()));
                i += 2;
                continue;
            }
        } else if let Some(val) = arg.strip_prefix("--cgroup-parent=") {
            cmd.dangerous_flags
                .push(DangerousFlag::CgroupParent(val.to_string()));
            i += 1;
            continue;
        }

        // --ipc
        if arg == "--ipc" {
            if i + 1 < args.len() {
                let val = args[i + 1];
                if val == "host" {
                    cmd.dangerous_flags.push(DangerousFlag::IpcHost);
                } else if let Some(name) = val.strip_prefix("container:") {
                    cmd.dangerous_flags
                        .push(DangerousFlag::IpcContainer(name.to_string()));
                }
                i += 2;
                continue;
            }
        } else if let Some(val) = arg.strip_prefix("--ipc=") {
            if val == "host" {
                cmd.dangerous_flags.push(DangerousFlag::IpcHost);
            } else if let Some(name) = val.strip_prefix("container:") {
                cmd.dangerous_flags
                    .push(DangerousFlag::IpcContainer(name.to_string()));
            }
            i += 1;
            continue;
        }

        // --uts
        if arg == "--uts" {
            if i + 1 < args.len() {
                if args[i + 1] == "host" {
                    cmd.dangerous_flags.push(DangerousFlag::UtsHost);
                }
                i += 2;
                continue;
            }
        } else if let Some(val) = arg.strip_prefix("--uts=") {
            if val == "host" {
                cmd.dangerous_flags.push(DangerousFlag::UtsHost);
            }
            i += 1;
            continue;
        }

        // --env-file (ホストファイル読み取り → パス検証)
        if arg == "--env-file" {
            if i + 1 < args.len() {
                cmd.host_paths.push(args[i + 1].to_string());
                i += 2;
                continue;
            }
        } else if let Some(value) = arg.strip_prefix("--env-file=") {
            cmd.host_paths.push(value.to_string());
            i += 1;
            continue;
        }

        // --label-file (ホストファイル読み取り → パス検証)
        if arg == "--label-file" {
            if i + 1 < args.len() {
                cmd.host_paths.push(args[i + 1].to_string());
                i += 2;
                continue;
            }
        } else if let Some(value) = arg.strip_prefix("--label-file=") {
            cmd.host_paths.push(value.to_string());
            i += 1;
            continue;
        }

        // --sysctl (カーネルパラメータ → 危険値検出)
        if arg == "--sysctl" {
            if i + 1 < args.len() {
                cmd.dangerous_flags
                    .push(DangerousFlag::Sysctl(args[i + 1].to_string()));
                i += 2;
                continue;
            }
        } else if let Some(value) = arg.strip_prefix("--sysctl=") {
            cmd.dangerous_flags
                .push(DangerousFlag::Sysctl(value.to_string()));
            i += 1;
            continue;
        }

        // --add-host (メタデータ IP 検出)
        if arg == "--add-host" {
            if i + 1 < args.len() {
                cmd.dangerous_flags
                    .push(DangerousFlag::AddHost(args[i + 1].to_string()));
                i += 2;
                continue;
            }
        } else if let Some(value) = arg.strip_prefix("--add-host=") {
            cmd.dangerous_flags
                .push(DangerousFlag::AddHost(value.to_string()));
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

        // --build-arg: 機密情報パターン検出
        if arg == "--build-arg" {
            if i + 1 < args.len() {
                if is_secret_build_arg(args[i + 1]) {
                    cmd.dangerous_flags
                        .push(DangerousFlag::BuildArgSecret(args[i + 1].to_string()));
                }
                i += 2;
                continue;
            }
        } else if let Some(value) = arg.strip_prefix("--build-arg=") {
            if is_secret_build_arg(value) {
                cmd.dangerous_flags
                    .push(DangerousFlag::BuildArgSecret(value.to_string()));
            }
            i += 1;
            continue;
        }

        // --secret: BuildKit secret のソースパス検証
        if arg == "--secret" {
            if i + 1 < args.len() {
                if let Some(path) = extract_build_secret_path(args[i + 1]) {
                    cmd.host_paths.push(path);
                }
                i += 2;
                continue;
            }
        } else if let Some(value) = arg.strip_prefix("--secret=") {
            if let Some(path) = extract_build_secret_path(value) {
                cmd.host_paths.push(path);
            }
            i += 1;
            continue;
        }

        // --ssh: BuildKit SSH 転送のソースパス検証
        if arg == "--ssh" {
            if i + 1 < args.len() {
                if let Some(path) = extract_build_secret_path(args[i + 1]) {
                    cmd.host_paths.push(path);
                }
                i += 2;
                continue;
            }
        } else if let Some(value) = arg.strip_prefix("--ssh=") {
            if let Some(path) = extract_build_secret_path(value) {
                cmd.host_paths.push(path);
            }
            i += 1;
            continue;
        }

        // 値を取るフラグをスキップ
        if matches!(
            arg,
            "-f" | "--file"
                | "-t"
                | "--tag"
                | "--target"
                | "--platform"
                | "--label"
                | "--cache-from"
                | "--network"
                | "--progress"
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
                        if let Some(bm) = parse_volume_flag(args[i + 1], &mut cmd.dangerous_flags) {
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
            | "--uts"
            | "--pid"
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
            | "--env-file"
            | "--label-file"
            | "--device-cgroup-rule"
            | "--device-read-bps"
            | "--device-write-bps"
            | "--device-read-iops"
            | "--device-write-iops"
            | "--blkio-weight"
            | "--blkio-weight-device"
            | "-c"
            | "--cpu-shares"
            | "--cpuset-cpus"
            | "--cpuset-mems"
            | "--cpu-period"
            | "--cpu-quota"
            | "--memory-swap"
            | "--memory-swappiness"
            | "--memory-reservation"
            | "--kernel-memory"
            | "--pids-limit"
            | "--group-add"
            | "--domainname"
            | "--oom-score-adj"
            | "--isolation"
            | "--ip6"
            | "--dns-search"
            | "--dns-option"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_volume_short() {
        let bm = parse_volume_flag("/host/path:/container/path", &mut vec![]).unwrap();
        assert_eq!(bm.host_path, "/host/path");
        assert_eq!(bm.container_path, "/container/path");
        assert!(!bm.read_only);
    }

    #[test]
    fn test_parse_volume_readonly() {
        let bm = parse_volume_flag("/host:/container:ro", &mut vec![]).unwrap();
        assert!(bm.read_only);
    }

    #[test]
    fn test_parse_volume_named() {
        assert!(parse_volume_flag("myvolume:/container", &mut vec![]).is_none());
    }

    #[test]
    fn test_parse_volume_home() {
        let bm = parse_volume_flag("~/projects:/app", &mut vec![]).unwrap();
        assert_eq!(bm.host_path, "~/projects");
    }

    #[test]
    fn test_parse_volume_relative() {
        let bm = parse_volume_flag("./src:/app/src", &mut vec![]).unwrap();
        assert_eq!(bm.host_path, "./src");
    }

    #[test]
    fn test_parse_mount_bind() {
        let bm = parse_mount_flag(
            "type=bind,source=/host/path,target=/container/path",
            &mut vec![],
        )
        .unwrap();
        assert_eq!(bm.host_path, "/host/path");
        assert_eq!(bm.container_path, "/container/path");
        assert!(!bm.read_only);
    }

    #[test]
    fn test_parse_mount_readonly() {
        let bm = parse_mount_flag(
            "type=bind,source=/host,target=/container,readonly",
            &mut vec![],
        )
        .unwrap();
        assert!(bm.read_only);
    }

    #[test]
    fn test_parse_mount_volume_type() {
        assert!(parse_mount_flag("type=volume,source=myvol,target=/data", &mut vec![]).is_none());
    }

    #[test]
    fn test_parse_mount_src_dst() {
        let bm = parse_mount_flag("type=bind,src=/host,dst=/container", &mut vec![]).unwrap();
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

    // --- A: コンテナ間 namespace 共有テスト ---

    #[test]
    fn test_parse_network_container_equals() {
        let args = vec!["run", "--network=container:db", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(matches!(
            &cmd.dangerous_flags[0],
            DangerousFlag::NetworkContainer(n) if n == "db"
        ));
    }

    #[test]
    fn test_parse_network_container_space() {
        let args = vec!["run", "--network", "container:web", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(matches!(
            &cmd.dangerous_flags[0],
            DangerousFlag::NetworkContainer(n) if n == "web"
        ));
    }

    #[test]
    fn test_parse_net_container_equals() {
        let args = vec!["run", "--net=container:redis", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(matches!(
            &cmd.dangerous_flags[0],
            DangerousFlag::NetworkContainer(n) if n == "redis"
        ));
    }

    #[test]
    fn test_parse_pid_container_equals() {
        let args = vec!["run", "--pid=container:app", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(matches!(
            &cmd.dangerous_flags[0],
            DangerousFlag::PidContainer(n) if n == "app"
        ));
    }

    #[test]
    fn test_parse_pid_container_space() {
        let args = vec!["run", "--pid", "container:app", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(matches!(
            &cmd.dangerous_flags[0],
            DangerousFlag::PidContainer(n) if n == "app"
        ));
    }

    #[test]
    fn test_parse_ipc_container_equals() {
        let args = vec!["run", "--ipc=container:shm", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(matches!(
            &cmd.dangerous_flags[0],
            DangerousFlag::IpcContainer(n) if n == "shm"
        ));
    }

    #[test]
    fn test_parse_ipc_container_space() {
        let args = vec!["run", "--ipc", "container:shm", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(matches!(
            &cmd.dangerous_flags[0],
            DangerousFlag::IpcContainer(n) if n == "shm"
        ));
    }

    #[test]
    fn test_parse_network_bridge_no_flag() {
        // bridge は通常のネットワークモードなので検出しない
        let args = vec!["run", "--network=bridge", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(cmd.dangerous_flags.is_empty());
    }

    // --- B: mount propagation テスト ---

    #[test]
    fn test_parse_volume_propagation_shared() {
        let mut flags = vec![];
        parse_volume_flag("/host:/container:shared", &mut flags);
        assert!(matches!(
            &flags[0],
            DangerousFlag::MountPropagation(m) if m == "shared"
        ));
    }

    #[test]
    fn test_parse_volume_propagation_rshared() {
        let mut flags = vec![];
        parse_volume_flag("/host:/container:ro,rshared", &mut flags);
        assert!(matches!(
            &flags[0],
            DangerousFlag::MountPropagation(m) if m == "rshared"
        ));
    }

    #[test]
    fn test_parse_volume_propagation_private_safe() {
        // private は安全なのでフラグを出さない
        let mut flags = vec![];
        parse_volume_flag("/host:/container:private", &mut flags);
        assert!(flags.is_empty());
    }

    #[test]
    fn test_parse_mount_propagation_shared() {
        let mut flags = vec![];
        parse_mount_flag(
            "type=bind,source=/host,target=/container,bind-propagation=shared",
            &mut flags,
        );
        assert!(matches!(
            &flags[0],
            DangerousFlag::MountPropagation(m) if m == "shared"
        ));
    }

    #[test]
    fn test_parse_mount_propagation_rshared() {
        let mut flags = vec![];
        parse_mount_flag(
            "type=bind,source=/host,target=/container,bind-propagation=rshared",
            &mut flags,
        );
        assert!(matches!(
            &flags[0],
            DangerousFlag::MountPropagation(m) if m == "rshared"
        ));
    }

    #[test]
    fn test_parse_mount_propagation_private_safe() {
        let mut flags = vec![];
        parse_mount_flag(
            "type=bind,source=/host,target=/container,bind-propagation=private",
            &mut flags,
        );
        assert!(flags.is_empty());
    }

    #[test]
    fn test_parse_docker_run_propagation_detected() {
        let args = vec!["run", "-v", "/host:/container:shared", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(
            cmd.dangerous_flags
                .iter()
                .any(|f| matches!(f, DangerousFlag::MountPropagation(_)))
        );
    }

    #[test]
    fn test_parse_docker_run_mount_propagation_detected() {
        let args = vec![
            "run",
            "--mount",
            "type=bind,source=/host,target=/mnt,bind-propagation=rshared",
            "ubuntu",
        ];
        let cmd = parse_docker_args(&args);
        assert!(
            cmd.dangerous_flags
                .iter()
                .any(|f| matches!(f, DangerousFlag::MountPropagation(_)))
        );
    }

    // --- Phase 5a: --uts=host ---

    #[test]
    fn test_parse_uts_host_equals() {
        let args = vec!["run", "--uts=host", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(cmd.dangerous_flags.contains(&DangerousFlag::UtsHost));
    }

    #[test]
    fn test_parse_uts_host_space() {
        let args = vec!["run", "--uts", "host", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(cmd.dangerous_flags.contains(&DangerousFlag::UtsHost));
    }

    #[test]
    fn test_parse_uts_non_host_no_flag() {
        let args = vec!["run", "--uts=private", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(!cmd.dangerous_flags.contains(&DangerousFlag::UtsHost));
    }

    #[test]
    fn test_parse_uts_space_consumes_value() {
        // --uts の値がイメージ名として誤認されないこと
        let args = vec!["run", "--uts", "private", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.image, Some("ubuntu".to_string()));
        assert!(!cmd.dangerous_flags.contains(&DangerousFlag::UtsHost));
    }

    // --- Phase 5a: is_flag_with_value 補完 ---

    #[test]
    fn test_is_flag_with_value_new_flags() {
        assert!(is_flag_with_value("--env-file"));
        assert!(is_flag_with_value("--label-file"));
        assert!(is_flag_with_value("--uts"));
        assert!(is_flag_with_value("--pid"));
        assert!(is_flag_with_value("--device-read-bps"));
        assert!(is_flag_with_value("--device-write-bps"));
        assert!(is_flag_with_value("--cpu-shares"));
        assert!(is_flag_with_value("-c"));
        assert!(is_flag_with_value("--pids-limit"));
        assert!(is_flag_with_value("--memory-swap"));
        assert!(is_flag_with_value("--group-add"));
        assert!(is_flag_with_value("--dns-search"));
    }

    #[test]
    fn test_env_file_not_eaten_as_image() {
        // --env-file の値がイメージ名として誤認されないこと
        let args = vec![
            "run",
            "--env-file",
            "/home/user/.env",
            "--privileged",
            "ubuntu",
        ];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.image, Some("ubuntu".to_string()));
        assert!(cmd.dangerous_flags.contains(&DangerousFlag::Privileged));
    }

    #[test]
    fn test_pids_limit_not_eaten_as_image() {
        // --pids-limit の値がイメージ名として誤認されないこと
        let args = vec!["run", "--pids-limit", "100", "--privileged", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.image, Some("ubuntu".to_string()));
        assert!(cmd.dangerous_flags.contains(&DangerousFlag::Privileged));
    }

    // --- Phase 5b: --env-file / --label-file パス検証 ---

    #[test]
    fn test_parse_env_file_space() {
        let args = vec!["run", "--env-file", "/etc/secrets.env", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(cmd.host_paths.contains(&"/etc/secrets.env".to_string()));
    }

    #[test]
    fn test_parse_env_file_equals() {
        let args = vec!["run", "--env-file=/etc/secrets.env", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(cmd.host_paths.contains(&"/etc/secrets.env".to_string()));
    }

    #[test]
    fn test_parse_label_file_space() {
        let args = vec!["run", "--label-file", "/etc/labels", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(cmd.host_paths.contains(&"/etc/labels".to_string()));
    }

    #[test]
    fn test_parse_label_file_equals() {
        let args = vec!["run", "--label-file=/etc/labels", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(cmd.host_paths.contains(&"/etc/labels".to_string()));
    }

    // --- Phase 5b: --security-opt seccomp=PATH パス検証 ---

    #[test]
    fn test_parse_seccomp_profile_path() {
        let args = vec![
            "run",
            "--security-opt",
            "seccomp=/etc/docker/seccomp.json",
            "ubuntu",
        ];
        let cmd = parse_docker_args(&args);
        assert!(
            cmd.host_paths
                .contains(&"/etc/docker/seccomp.json".to_string())
        );
        // SecurityOpt としても記録される
        assert!(
            cmd.dangerous_flags
                .iter()
                .any(|f| matches!(f, DangerousFlag::SecurityOpt(_)))
        );
    }

    #[test]
    fn test_parse_seccomp_profile_path_equals() {
        let args = vec![
            "run",
            "--security-opt=seccomp=/opt/profiles/sec.json",
            "ubuntu",
        ];
        let cmd = parse_docker_args(&args);
        assert!(
            cmd.host_paths
                .contains(&"/opt/profiles/sec.json".to_string())
        );
    }

    #[test]
    fn test_parse_seccomp_profile_path_colon() {
        let args = vec!["run", "--security-opt", "seccomp:/opt/sec.json", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(cmd.host_paths.contains(&"/opt/sec.json".to_string()));
    }

    #[test]
    fn test_parse_seccomp_unconfined_no_path() {
        let args = vec!["run", "--security-opt", "seccomp=unconfined", "ubuntu"];
        let cmd = parse_docker_args(&args);
        // unconfined はパスとして扱わない
        assert!(cmd.host_paths.is_empty());
    }

    #[test]
    fn test_parse_apparmor_opt_no_path() {
        let args = vec!["run", "--security-opt", "apparmor=unconfined", "ubuntu"];
        let cmd = parse_docker_args(&args);
        // apparmor は seccomp パス検出の対象外
        assert!(cmd.host_paths.is_empty());
    }

    // --- Phase 5d: --sysctl ---

    #[test]
    fn test_parse_sysctl_equals() {
        let args = vec!["run", "--sysctl=kernel.shmmax=65536", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(matches!(
            &cmd.dangerous_flags[0],
            DangerousFlag::Sysctl(v) if v == "kernel.shmmax=65536"
        ));
    }

    #[test]
    fn test_parse_sysctl_space() {
        let args = vec!["run", "--sysctl", "net.ipv4.ip_forward=1", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(matches!(
            &cmd.dangerous_flags[0],
            DangerousFlag::Sysctl(v) if v == "net.ipv4.ip_forward=1"
        ));
    }

    #[test]
    fn test_parse_sysctl_not_eaten_as_image() {
        let args = vec![
            "run",
            "--sysctl",
            "net.core.somaxconn=1024",
            "--privileged",
            "ubuntu",
        ];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.image, Some("ubuntu".to_string()));
        assert!(cmd.dangerous_flags.contains(&DangerousFlag::Privileged));
    }

    #[test]
    fn test_parse_multiple_sysctls() {
        let args = vec![
            "run",
            "--sysctl",
            "kernel.shmmax=65536",
            "--sysctl=net.ipv4.ip_forward=1",
            "ubuntu",
        ];
        let cmd = parse_docker_args(&args);
        let sysctls: Vec<_> = cmd
            .dangerous_flags
            .iter()
            .filter(|f| matches!(f, DangerousFlag::Sysctl(_)))
            .collect();
        assert_eq!(sysctls.len(), 2);
    }

    // --- Phase 5d: --add-host ---

    #[test]
    fn test_parse_add_host_equals() {
        let args = vec!["run", "--add-host=metadata:169.254.169.254", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(matches!(
            &cmd.dangerous_flags[0],
            DangerousFlag::AddHost(v) if v == "metadata:169.254.169.254"
        ));
    }

    #[test]
    fn test_parse_add_host_space() {
        let args = vec!["run", "--add-host", "myhost:192.168.1.1", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(matches!(
            &cmd.dangerous_flags[0],
            DangerousFlag::AddHost(v) if v == "myhost:192.168.1.1"
        ));
    }

    #[test]
    fn test_parse_add_host_not_eaten_as_image() {
        let args = vec![
            "run",
            "--add-host",
            "myhost:10.0.0.1",
            "--privileged",
            "ubuntu",
        ];
        let cmd = parse_docker_args(&args);
        assert_eq!(cmd.image, Some("ubuntu".to_string()));
        assert!(cmd.dangerous_flags.contains(&DangerousFlag::Privileged));
    }

    // --- Phase 5e: --build-arg secret detection ---

    #[test]
    fn test_is_secret_build_arg_patterns() {
        assert!(is_secret_build_arg("DB_PASSWORD=hunter2"));
        assert!(is_secret_build_arg("API_TOKEN=abc123"));
        assert!(is_secret_build_arg("MY_SECRET=value"));
        assert!(is_secret_build_arg("AWS_SECRET_KEY=xxx"));
        assert!(is_secret_build_arg("GITHUB_APIKEY=xxx"));
        assert!(is_secret_build_arg("API_KEY=xxx"));
        assert!(is_secret_build_arg("PRIVATE_KEY=xxx"));
        assert!(is_secret_build_arg("DB_CREDENTIAL=xxx"));
        assert!(is_secret_build_arg("PASSWD_HASH=xxx"));
        // KEY patterns
        assert!(is_secret_build_arg("AWS_ACCESS_KEY=xxx"));
        assert!(is_secret_build_arg("MY_KEY_FILE=xxx"));
        assert!(is_secret_build_arg("KEY=value"));
        // Not secret patterns
        assert!(!is_secret_build_arg("APP_VERSION=1.0"));
        assert!(!is_secret_build_arg("BUILD_NUMBER=42"));
        assert!(!is_secret_build_arg("NODE_ENV=production"));
        assert!(!is_secret_build_arg("MONKEY=banana"));
    }

    #[test]
    fn test_parse_build_arg_secret_space() {
        let args = vec!["build", "--build-arg", "DB_PASSWORD=secret123", "."];
        let cmd = parse_docker_args(&args);
        assert!(matches!(
            &cmd.dangerous_flags[0],
            DangerousFlag::BuildArgSecret(v) if v == "DB_PASSWORD=secret123"
        ));
    }

    #[test]
    fn test_parse_build_arg_secret_equals() {
        let args = vec!["build", "--build-arg=API_TOKEN=abc", "."];
        let cmd = parse_docker_args(&args);
        assert!(matches!(
            &cmd.dangerous_flags[0],
            DangerousFlag::BuildArgSecret(v) if v == "API_TOKEN=abc"
        ));
    }

    #[test]
    fn test_parse_build_arg_safe_no_flag() {
        let args = vec!["build", "--build-arg", "APP_VERSION=1.0", "."];
        let cmd = parse_docker_args(&args);
        assert!(
            cmd.dangerous_flags.is_empty(),
            "Non-secret build-arg should not produce flag"
        );
    }

    #[test]
    fn test_parse_build_arg_key_only() {
        // --build-arg TOKEN (no =VALUE, sets from env)
        let args = vec!["build", "--build-arg", "TOKEN", "."];
        let cmd = parse_docker_args(&args);
        assert!(matches!(
            &cmd.dangerous_flags[0],
            DangerousFlag::BuildArgSecret(v) if v == "TOKEN"
        ));
    }

    // --- Phase 5e: --secret / --ssh path extraction ---

    #[test]
    fn test_extract_build_secret_path_src() {
        assert_eq!(
            extract_build_secret_path("id=mysecret,src=/etc/secret.txt"),
            Some("/etc/secret.txt".to_string())
        );
    }

    #[test]
    fn test_extract_build_secret_path_source() {
        assert_eq!(
            extract_build_secret_path("id=mysecret,source=/home/user/.env"),
            Some("/home/user/.env".to_string())
        );
    }

    #[test]
    fn test_extract_build_secret_path_no_src() {
        assert_eq!(extract_build_secret_path("id=mysecret"), None);
    }

    #[test]
    fn test_extract_build_secret_path_default_ssh() {
        assert_eq!(extract_build_secret_path("default"), None);
    }

    #[test]
    fn test_parse_build_secret_path_in_host_paths() {
        let args = vec!["build", "--secret", "id=db,src=/etc/db.env", "."];
        let cmd = parse_docker_args(&args);
        assert!(cmd.host_paths.contains(&"/etc/db.env".to_string()));
    }

    #[test]
    fn test_parse_build_secret_equals_path_in_host_paths() {
        let args = vec!["build", "--secret=id=key,src=/etc/key.pem", "."];
        let cmd = parse_docker_args(&args);
        assert!(cmd.host_paths.contains(&"/etc/key.pem".to_string()));
    }

    #[test]
    fn test_parse_build_ssh_path_in_host_paths() {
        let args = vec!["build", "--ssh", "id=mykey,src=/etc/ssh/id_rsa", "."];
        let cmd = parse_docker_args(&args);
        assert!(cmd.host_paths.contains(&"/etc/ssh/id_rsa".to_string()));
    }

    #[test]
    fn test_parse_build_ssh_default_no_path() {
        let args = vec!["build", "--ssh", "default", "."];
        let cmd = parse_docker_args(&args);
        // "default" has no src, so no host path
        let non_context_paths: Vec<_> = cmd.host_paths.iter().filter(|p| *p != ".").collect();
        assert!(non_context_paths.is_empty());
    }

    // --- is_flag_with_value() リグレッション防止テスト ---
    //
    // is_flag_with_value() に漏れがあると、フラグの値が後続の引数として
    // 誤認され、危険フラグの検出が失敗する。
    // 各フラグについて「フラグ + 値 + --privileged」の組み合わせで
    // --privileged が確実に検出されることを検証する。

    /// is_flag_with_value() 内のフラグと値の後に --privileged を配置し、
    /// --privileged が検出されることを確認するヘルパー
    fn assert_privileged_detected_after_flag(flag: &str, value: &str) {
        let args = vec!["run", flag, value, "--privileged", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(
            cmd.dangerous_flags
                .iter()
                .any(|f| matches!(f, DangerousFlag::Privileged)),
            "--privileged should be detected after '{}' '{}', but got: {:?}",
            flag,
            value,
            cmd.dangerous_flags
        );
    }

    #[test]
    fn test_flag_with_value_env() {
        assert_privileged_detected_after_flag("-e", "FOO=bar");
        assert_privileged_detected_after_flag("--env", "FOO=bar");
    }

    #[test]
    fn test_flag_with_value_name() {
        assert_privileged_detected_after_flag("--name", "mycontainer");
    }

    #[test]
    fn test_flag_with_value_workdir() {
        assert_privileged_detected_after_flag("-w", "/app");
        assert_privileged_detected_after_flag("--workdir", "/app");
    }

    #[test]
    fn test_flag_with_value_publish() {
        assert_privileged_detected_after_flag("-p", "8080:80");
        assert_privileged_detected_after_flag("--publish", "8080:80");
    }

    #[test]
    fn test_flag_with_value_label() {
        assert_privileged_detected_after_flag("-l", "app=web");
        assert_privileged_detected_after_flag("--label", "app=web");
    }

    #[test]
    fn test_flag_with_value_hostname() {
        assert_privileged_detected_after_flag("--hostname", "myhost");
        assert_privileged_detected_after_flag("-h", "myhost");
    }

    #[test]
    fn test_flag_with_value_user() {
        assert_privileged_detected_after_flag("-u", "1000");
        assert_privileged_detected_after_flag("--user", "root");
    }

    #[test]
    fn test_flag_with_value_entrypoint() {
        assert_privileged_detected_after_flag("--entrypoint", "/bin/sh");
    }

    #[test]
    fn test_flag_with_value_restart() {
        assert_privileged_detected_after_flag("--restart", "always");
    }

    #[test]
    fn test_flag_with_value_memory() {
        assert_privileged_detected_after_flag("-m", "512m");
        assert_privileged_detected_after_flag("--memory", "1g");
    }

    #[test]
    fn test_flag_with_value_cpus() {
        assert_privileged_detected_after_flag("--cpus", "2.0");
    }

    #[test]
    fn test_flag_with_value_log() {
        assert_privileged_detected_after_flag("--log-driver", "json-file");
        assert_privileged_detected_after_flag("--log-opt", "max-size=10m");
    }

    #[test]
    fn test_flag_with_value_network() {
        // --network with non-host value should skip value, detect --privileged
        let args = vec!["run", "--network", "bridge", "--privileged", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(
            cmd.dangerous_flags
                .iter()
                .any(|f| matches!(f, DangerousFlag::Privileged))
        );
    }

    #[test]
    fn test_flag_with_value_dns() {
        assert_privileged_detected_after_flag("--dns", "8.8.8.8");
    }

    #[test]
    fn test_flag_with_value_tmpfs() {
        assert_privileged_detected_after_flag("--tmpfs", "/run");
    }

    #[test]
    fn test_flag_with_value_shm_size() {
        assert_privileged_detected_after_flag("--shm-size", "2g");
    }

    #[test]
    fn test_flag_with_value_ulimit() {
        assert_privileged_detected_after_flag("--ulimit", "nofile=1024:1024");
    }

    #[test]
    fn test_flag_with_value_platform() {
        assert_privileged_detected_after_flag("--platform", "linux/amd64");
    }

    #[test]
    fn test_flag_with_value_pull() {
        assert_privileged_detected_after_flag("--pull", "always");
    }

    #[test]
    fn test_flag_with_value_volumes_from() {
        assert_privileged_detected_after_flag("--volumes-from", "container1");
    }

    #[test]
    fn test_flag_with_value_runtime() {
        assert_privileged_detected_after_flag("--runtime", "nvidia");
    }

    #[test]
    fn test_flag_with_value_cgroup_parent() {
        assert_privileged_detected_after_flag("--cgroup-parent", "/my/cgroup");
    }

    #[test]
    fn test_flag_with_value_cidfile() {
        assert_privileged_detected_after_flag("--cidfile", "/tmp/cid");
    }

    #[test]
    fn test_flag_with_value_mac_address() {
        assert_privileged_detected_after_flag("--mac-address", "92:d0:c6:0a:29:33");
    }

    #[test]
    fn test_flag_with_value_storage_opt() {
        assert_privileged_detected_after_flag("--storage-opt", "size=120G");
    }

    #[test]
    fn test_flag_with_value_gpus() {
        assert_privileged_detected_after_flag("--gpus", "all");
    }

    #[test]
    fn test_flag_with_value_attach() {
        assert_privileged_detected_after_flag("-a", "stdin");
        assert_privileged_detected_after_flag("--attach", "stdout");
    }

    #[test]
    fn test_flag_with_value_link() {
        assert_privileged_detected_after_flag("--link", "db:database");
    }

    #[test]
    fn test_flag_with_value_env_file() {
        assert_privileged_detected_after_flag("--env-file", "/tmp/.env");
    }

    #[test]
    fn test_flag_with_value_cpu_shares() {
        assert_privileged_detected_after_flag("-c", "512");
        assert_privileged_detected_after_flag("--cpu-shares", "512");
    }

    #[test]
    fn test_flag_with_value_cpuset() {
        assert_privileged_detected_after_flag("--cpuset-cpus", "0-3");
        assert_privileged_detected_after_flag("--cpuset-mems", "0");
    }

    #[test]
    fn test_flag_with_value_resource_limits() {
        assert_privileged_detected_after_flag("--cpu-period", "100000");
        assert_privileged_detected_after_flag("--cpu-quota", "50000");
        assert_privileged_detected_after_flag("--memory-swap", "1g");
        assert_privileged_detected_after_flag("--memory-reservation", "512m");
        assert_privileged_detected_after_flag("--pids-limit", "100");
    }

    #[test]
    fn test_flag_with_value_misc() {
        assert_privileged_detected_after_flag("--group-add", "video");
        assert_privileged_detected_after_flag("--domainname", "example.com");
        assert_privileged_detected_after_flag("--oom-score-adj", "100");
        assert_privileged_detected_after_flag("--isolation", "process");
        assert_privileged_detected_after_flag("--ip6", "::1");
        assert_privileged_detected_after_flag("--dns-search", "example.com");
        assert_privileged_detected_after_flag("--dns-option", "ndots:5");
    }

    // --- 複合フラグの組み合わせテスト ---

    #[test]
    fn test_compound_flags_short_and_long() {
        // 短形式と長形式を混在させても全てのフラグが正しく認識される
        let args = vec![
            "run",
            "-e",
            "FOO=bar",
            "--name",
            "mycontainer",
            "-p",
            "8080:80",
            "-v",
            "/etc:/data",
            "--privileged",
            "ubuntu",
        ];
        let cmd = parse_docker_args(&args);
        assert!(
            cmd.dangerous_flags
                .iter()
                .any(|f| matches!(f, DangerousFlag::Privileged))
        );
        assert_eq!(cmd.bind_mounts.len(), 1);
        assert_eq!(cmd.bind_mounts[0].host_path, "/etc");
    }

    #[test]
    fn test_compound_many_flags_before_dangerous() {
        // 多数の値付きフラグの後に危険フラグがあっても検出される
        let args = vec![
            "run",
            "-e",
            "A=1",
            "-e",
            "B=2",
            "-l",
            "x=y",
            "--name",
            "c",
            "-w",
            "/app",
            "-u",
            "1000",
            "--restart",
            "always",
            "--log-driver",
            "json-file",
            "--network=host",
            "ubuntu",
        ];
        let cmd = parse_docker_args(&args);
        assert!(
            cmd.dangerous_flags
                .iter()
                .any(|f| matches!(f, DangerousFlag::NetworkHost)),
            "network=host should be detected after many flags: {:?}",
            cmd.dangerous_flags
        );
    }

    #[test]
    fn test_equals_form_does_not_consume_next_arg() {
        // --network=bridge は値が = で結合されているので次の引数を消費しない
        let args = vec!["run", "--network=bridge", "--privileged", "ubuntu"];
        let cmd = parse_docker_args(&args);
        assert!(
            cmd.dangerous_flags
                .iter()
                .any(|f| matches!(f, DangerousFlag::Privileged))
        );
    }
}
