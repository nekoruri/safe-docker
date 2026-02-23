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

# バインドマウントパスを $HOME 配下のみに制限
deny if {
    bm := input.BindMounts[_]
    resolved := bm.Resolved
    resolved != ""
    not startswith(resolved, "/home/masa/")
}

# Source が $HOME 配下でもリンク先が異なる場合を検出
deny if {
    bm := input.BindMounts[_]
    startswith(bm.Source, "/home/masa/")
    bm.Resolved != ""
    not startswith(bm.Resolved, "/home/masa/")
}

# --privileged をブロック
deny if {
    input.Body.HostConfig.Privileged == true
}

# 危険な capability をブロック
deny if {
    cap := input.Body.HostConfig.CapAdd[_]
    cap in {"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO", "ALL"}
}

# Docker ソケットのマウントを禁止
deny if {
    bm := input.BindMounts[_]
    bm.Resolved == "/var/run/docker.sock"
}
