# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.1] - 2026-03-01

### Added

- `cargo audit` CI workflow (weekly schedule + push/PR triggers)
- Dependabot configuration for Cargo and GitHub Actions dependencies with grouping
- Code coverage measurement with `cargo-llvm-cov` and Codecov integration
- `codecov.yml` quality gates (project 90%, patch 80%)
- `musl` static binary added to release targets
- CI, Security Audit, and Codecov badges in README

### Changed

- Refactor `is_flag_with_value` to table-driven `VALUE_FLAGS` constant with categorized entries
- Add `[lints]` section to `Cargo.toml` for centralized lint management (replaces `RUSTFLAGS` / `-- -D warnings`)
- Expand `.gitignore` with editor, OS, and screenshot patterns

### Fixed

- Documentation inconsistencies (DOC-01 through DOC-09)

## [0.8.0] - 2026-03-01

### Added

- Hand-rolled OTLP struct definitions in `otlp_types.rs` with proto3 JSON mapping compliance
- Compose `volumes_from` detection (deny when referencing external service data)
- Compose `cgroup_parent` detection (`DangerousFlag::CgroupParent`)
- Compose `driver_opts.device` bind mount spoofing detection
- `is_flag_with_value()` regression prevention tests
- Comprehensive tests for `shell.rs` (14 → 62 tests)
- Non-interactive ask tests with config file override for wrapper mode
- Edge case tests for `audit.rs` environment and JSONL output
- Compose mount propagation detection in volumes (`shared`/`rshared`)

### Changed

- Replace `serde_yml` with `serde_yaml_ng` (RUSTSEC-2025-0068 advisory)
- Remove `opentelemetry-proto` crate dependency in favor of hand-rolled structs
- Update yanked dependency crates

### Fixed

- Metadata IP normalization (prevent bypass via non-canonical IP representations)
- Compose `extra_hosts` bypass for metadata endpoint detection
- `KEY` pattern detection in `--build-arg` secret scanning
- Flaky `test_find_real_docker_config` with `env_lock` serialization

### Security

- Metadata IP normalization prevents bypass of `169.254.169.254` detection
- Compose `extra_hosts` now correctly detected for metadata endpoint access
- `volumes_from` and `cgroup_parent` in Compose files are now flagged

## [0.7.0] - 2026-02-28

### Added

- `safe-docker setup` subcommand for wrapper mode setup (symlink creation, PATH verification)
- OPA Docker AuthZ integration guide (`docs/OPA_DOCKER_AUTHZ.md`)
- OPA `authz.rego` expanded to match safe-docker defaults with consistency tests
- Pre-commit hook for `cargo fmt` check
- `TempEnvVar` RAII guard for safe environment variable manipulation in tests

## [0.6.0] - 2026-02-27

### Added

- `config_source` field in audit events for investigability
- Diagnostic improvements for config loading, docker detection, and verbose output
- macOS and Linux musl CI test jobs
- MSRV (Minimum Supported Rust Version) set to 1.88
- Large compose benchmarks and CI cache optimization
- `CONTRIBUTING.md` with dangerous flag addition checklist and `is_flag_with_value()` guide

### Fixed

- macOS symlinked path handling in `is_path_allowed`
- Cross-platform test failures found by multi-environment CI

## [0.5.0] - 2026-02-27

### Added

- `--uts=host` detection (CIS 5.11 compliance, `DangerousFlag::UtsHost`)
- `--env-file PATH` host path validation ($HOME-outside → deny, sensitive_paths → ask)
- `--label-file PATH` host path validation
- `--security-opt seccomp=PROFILE_PATH` path validation (non-`unconfined` paths verified)
- Compose `env_file:` path validation (string, list, and mapping formats)
- Compose `sysctls:` detection (list and mapping formats)
- Compose `include:` directive detection (external file references, $HOME-outside → ask)
- `--sysctl` dangerous value detection (`kernel.*` → deny, `net.*` → ask)
- `--add-host` metadata IP detection (`169.254.169.254`, `fd00:ec2::254` → ask)
- `--security-opt label=disable` / `label:disable` detection (CIS 5.2)
- `docker build --build-arg` secret pattern detection (`SECRET`, `PASSWORD`, `TOKEN`, `KEY` → ask)
- BuildKit `--secret` / `--ssh` flag source path validation ($HOME-outside → deny)
- Blocked capabilities expanded: `DAC_READ_SEARCH`, `NET_ADMIN`, `BPF`, `PERFMON`, `SYS_BOOT`

### Changed

- `is_flag_with_value()` supplemented with 25+ missing flags (`--env-file`, `--label-file`, `--uts`, `--pid`, `--device-*`, `--cpu-*`, etc.)

### Security

- Host file read prevention via `--env-file`, `--label-file`, and `--security-opt seccomp=` path validation
- Expanded capability blocking prevents container escape vectors (`DAC_READ_SEARCH`, `BPF`, etc.)
- Sysctl kernel namespace manipulation now blocked

## [0.4.0] - 2026-02-26

### Added

- GitHub Artifact Attestations (Sigstore-based signing)
- SHA256 checksum files included in releases
- Supply chain security documentation (`docs/SUPPLY_CHAIN_SECURITY.md`)
- Container-to-container namespace sharing detection (`--network/--pid/--ipc=container:NAME`)
- Mount propagation detection (`shared`/`rshared` → deny)
- Compose `container:`/`service:` namespace reference detection
- Context-specific tip messages (`generate_tips`) for wrapper mode
- Edge case tests for wrapper mode

### Changed

- README install section refreshed with verification procedures and `cargo install`
- `sensitive_paths` defaults expanded (`.terraform`, `.vault-token`, `.config/gh`, `.npmrc`, `.pypirc`)

### Security

- Namespace sharing between containers now detected and blocked
- Mount propagation flags (`shared`/`rshared`) denied to prevent host filesystem exposure

## [0.3.0] - 2026-02-26

### Added

- Wrapper mode: transparent `docker` command substitution via `argv[0]` detection
- Real docker binary discovery (config > environment variable > PATH auto-search)
- Recursive call prevention via `SAFE_DOCKER_ACTIVE` environment variable
- `--dry-run`, `--verbose`, `--help`, `--version`, `--docker-path` CLI options
- Interactive ask confirmation with TTY detection and non-interactive environment config
- `mode` field in audit log entries (distinguishes hook vs wrapper mode)

## [0.2.0] - 2026-02-26

### Added

- `--security-opt` dangerous value detection (`apparmor`, `seccomp`, `systempaths`, `no-new-privileges`)
- Namespace flag detection (`--userns`, `--cgroupns`, `--ipc`)
- `docker cp` / `docker build` host path validation
- `docker-compose.yml` dangerous setting detection (`privileged`, `network_mode`, `pid`, `cap_add`, `security_opt`, `devices`)
- `docker exec --privileged` detection
- `docker buildx build` support
- Audit logging (JSONL and OTLP JSON Lines)
- Property-based testing with proptest
- `--check-config` subcommand for configuration validation
- MIT/Apache-2.0 dual license

### Changed

- Improved error messages with actionable context and explanations

## [0.1.0] - 2026-02-25

### Added

- Initial release as a Claude Code PreToolUse hook
- stdin/stdout JSON protocol for hook mode
- Shell command splitting (pipes, chains, newlines)
- Docker CLI argument parsing (subcommands, flags, mounts)
- Path validation (environment variable expansion, normalization, `$HOME` boundary check)
- Policy evaluation engine (deny/ask/allow decisions)
- TOML configuration file support
- CI and release automation workflows

[Unreleased]: https://github.com/nekoruri/safe-docker/compare/v0.8.1...HEAD
[0.8.1]: https://github.com/nekoruri/safe-docker/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/nekoruri/safe-docker/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/nekoruri/safe-docker/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/nekoruri/safe-docker/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/nekoruri/safe-docker/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/nekoruri/safe-docker/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/nekoruri/safe-docker/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/nekoruri/safe-docker/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/nekoruri/safe-docker/releases/tag/v0.1.0
