package docker.authz

import rego.v1

default allow := false

# docker plugin 操作は常に許可（ロックアウト防止）
allow if {
    input.Path == "/Plugin.Disable"
}

allow if {
    input.Path == "/Plugin.Enable"
}

# deny ルールに引っかからなければ許可
allow if {
    not deny
}

# --privileged をブロック
deny if {
    input.Body.HostConfig.Privileged == true
}

# 危険な capability をブロック
# safe-docker の default_blocked_capabilities() と同期すること
deny if {
    cap := input.Body.HostConfig.CapAdd[_]
    cap in {
        "SYS_ADMIN",
        "SYS_PTRACE",
        "SYS_MODULE",
        "SYS_RAWIO",
        "DAC_READ_SEARCH",
        "NET_ADMIN",
        "BPF",
        "PERFMON",
        "SYS_BOOT",
        "ALL",
    }
}

# ホストの名前空間へのアクセスをブロック
deny if {
    input.Body.HostConfig.PidMode == "host"
}

deny if {
    input.Body.HostConfig.NetworkMode == "host"
}

deny if {
    input.Body.HostConfig.IpcMode == "host"
}

deny if {
    input.Body.HostConfig.UTSMode == "host"
}

deny if {
    input.Body.HostConfig.CgroupnsMode == "host"
}

deny if {
    input.Body.HostConfig.UsernsMode == "host"
}

# デバイスアクセスをブロック
deny if {
    count(input.Body.HostConfig.Devices) > 0
}

# 危険な security-opt をブロック
deny if {
    opt := input.Body.HostConfig.SecurityOpt[_]
    contains(opt, "apparmor=unconfined")
}

deny if {
    opt := input.Body.HostConfig.SecurityOpt[_]
    contains(opt, "seccomp=unconfined")
}

deny if {
    opt := input.Body.HostConfig.SecurityOpt[_]
    contains(opt, "label=disable")
}

deny if {
    opt := input.Body.HostConfig.SecurityOpt[_]
    contains(opt, "label:disable")
}

deny if {
    opt := input.Body.HostConfig.SecurityOpt[_]
    contains(opt, "no-new-privileges=false")
}

deny if {
    opt := input.Body.HostConfig.SecurityOpt[_]
    contains(opt, "systempaths=unconfined")
}

# バインドマウントパスを $HOME 配下のみに制限
# 注意: "/home/username/" を実際のユーザーのホームディレクトリに変更すること
deny if {
    bm := input.BindMounts[_]
    resolved := bm.Resolved
    resolved != ""
    not startswith(resolved, "/home/username/")
}

# Source が $HOME 配下でもリンク先が異なる場合を検出（パストラバーサル防止）
deny if {
    bm := input.BindMounts[_]
    startswith(bm.Source, "/home/username/")
    bm.Resolved != ""
    not startswith(bm.Resolved, "/home/username/")
}

# Docker ソケットのマウントを禁止
deny if {
    bm := input.BindMounts[_]
    bm.Resolved == "/var/run/docker.sock"
}
