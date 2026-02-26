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

fn make_bash_input_with_cwd(command: &str, cwd: &str) -> String {
    serde_json::json!({
        "session_id": "bench-session",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {
            "command": command,
            "description": "bench"
        },
        "cwd": cwd
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

// --- Large compose file benchmarks ---

/// Generate a compose file with the specified number of services.
/// Each service has volumes, environment variables, and labels.
fn generate_compose_file(num_services: usize) -> String {
    let home = home_dir();
    let mut content = String::from("services:\n");
    for i in 0..num_services {
        content.push_str(&format!("  service{i}:\n"));
        content.push_str(&format!("    image: ubuntu:latest\n"));
        content.push_str(&format!("    container_name: app-{i}\n"));
        content.push_str(&format!("    restart: unless-stopped\n"));
        // volumes (3 per service)
        content.push_str("    volumes:\n");
        for j in 0..3 {
            content.push_str(&format!(
                "      - {home}/data/svc{i}/vol{j}:/app/vol{j}:ro\n"
            ));
        }
        // environment variables (5 per service)
        content.push_str("    environment:\n");
        for j in 0..5 {
            content.push_str(&format!("      SVC{i}_VAR{j}: value{j}\n"));
        }
        // labels (3 per service)
        content.push_str("    labels:\n");
        for j in 0..3 {
            content.push_str(&format!(
                "      com.example.svc{i}.label{j}: \"label-value-{j}\"\n"
            ));
        }
        // ports (1 per service)
        content.push_str("    ports:\n");
        content.push_str(&format!("      - \"{}:{}\"\n", 8000 + i, 80));
    }
    content
}

fn bench_compose_10_services(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let compose_content = generate_compose_file(10);
    std::fs::write(dir.path().join("docker-compose.yml"), &compose_content).unwrap();
    let cwd = dir.path().to_str().unwrap();
    let input = make_bash_input_with_cwd("docker compose up", cwd);

    c.bench_function("compose_10_services", |b| {
        b.iter(|| run_hook_e2e(black_box(&input)))
    });
}

fn bench_compose_50_services(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let compose_content = generate_compose_file(50);
    std::fs::write(dir.path().join("docker-compose.yml"), &compose_content).unwrap();
    let cwd = dir.path().to_str().unwrap();
    let input = make_bash_input_with_cwd("docker compose up", cwd);

    c.bench_function("compose_50_services", |b| {
        b.iter(|| run_hook_e2e(black_box(&input)))
    });
}

fn bench_compose_100_services(c: &mut Criterion) {
    let dir = tempfile::tempdir().unwrap();
    let compose_content = generate_compose_file(100);
    std::fs::write(dir.path().join("docker-compose.yml"), &compose_content).unwrap();
    let cwd = dir.path().to_str().unwrap();
    let input = make_bash_input_with_cwd("docker compose up", cwd);

    c.bench_function("compose_100_services", |b| {
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
criterion_group!(
    compose_benches,
    bench_compose_10_services,
    bench_compose_50_services,
    bench_compose_100_services,
);
criterion_main!(benches, compose_benches);
