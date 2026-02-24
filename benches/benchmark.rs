use criterion::{Criterion, black_box, criterion_group, criterion_main};
use std::io::Write;
use std::process::{Command, Stdio};

fn home_dir() -> String {
    dirs::home_dir().unwrap().to_string_lossy().to_string()
}

fn make_bash_input(command: &str) -> String {
    serde_json::json!({
        "session_id": "bench-session",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": command,
            "description": "bench"
        },
        "cwd": "/tmp"
    })
    .to_string()
}

fn run_hook_e2e(input: &str) -> String {
    let mut child = Command::new(env!("CARGO_BIN_EXE_safe-docker"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn safe-docker");

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();

    let output = child.wait_with_output().unwrap();
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn bench_non_docker(c: &mut Criterion) {
    let input = make_bash_input("ls -la /tmp");
    c.bench_function("non_docker_command", |b| {
        b.iter(|| run_hook_e2e(black_box(&input)))
    });
}

fn bench_docker_no_mount(c: &mut Criterion) {
    let input = make_bash_input("docker run ubuntu echo hello");
    c.bench_function("docker_no_mount", |b| {
        b.iter(|| run_hook_e2e(black_box(&input)))
    });
}

fn bench_docker_allow_mount(c: &mut Criterion) {
    let cmd = format!("docker run -v {}/projects:/app ubuntu", home_dir());
    let input = make_bash_input(&cmd);
    c.bench_function("docker_allow_mount", |b| {
        b.iter(|| run_hook_e2e(black_box(&input)))
    });
}

fn bench_docker_deny_mount(c: &mut Criterion) {
    let input = make_bash_input("docker run -v /etc:/data ubuntu");
    c.bench_function("docker_deny_mount", |b| {
        b.iter(|| run_hook_e2e(black_box(&input)))
    });
}

fn bench_complex_piped(c: &mut Criterion) {
    let cmd = format!(
        "cd /tmp && echo test | docker run -v {}/src:/app -e FOO=bar --name test ubuntu cat /etc/hostname",
        home_dir()
    );
    let input = make_bash_input(&cmd);
    c.bench_function("complex_piped_command", |b| {
        b.iter(|| run_hook_e2e(black_box(&input)))
    });
}

fn bench_eval_docker(c: &mut Criterion) {
    let input = make_bash_input(r#"eval "docker run -v /etc:/data ubuntu""#);
    c.bench_function("eval_docker", |b| {
        b.iter(|| run_hook_e2e(black_box(&input)))
    });
}

criterion_group!(
    benches,
    bench_non_docker,
    bench_docker_no_mount,
    bench_docker_allow_mount,
    bench_docker_deny_mount,
    bench_complex_piped,
    bench_eval_docker,
);
criterion_main!(benches);
