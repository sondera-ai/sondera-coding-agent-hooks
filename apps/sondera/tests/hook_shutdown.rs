use std::io::Read;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn wait_for_exit(child: &mut Child, timeout_message: &str) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().expect("hook status should be readable") {
            return status;
        }
        if Instant::now() >= deadline {
            child.kill().expect("hung hook process should be killable");
            child.wait().expect("killed hook process should be reaped");
            panic!("{timeout_message}");
        }
        thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn timed_out_stdin_does_not_keep_the_hook_process_alive() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sondera"))
        .args(["hook", "gemini", "before-agent"])
        .env("SONDERA_HOOK_BUDGET_SECS", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("hook process should start");

    let status = wait_for_exit(
        &mut child,
        "hook process remained alive after its stdin deadline",
    );

    assert!(status.success(), "degraded Gemini hooks exit successfully");
    let mut stdout = String::new();
    child
        .stdout
        .take()
        .expect("stdout should be captured")
        .read_to_string(&mut stdout)
        .expect("stdout should be readable");
    assert!(stdout.contains("deny"), "hook should fail closed: {stdout}");
}

#[test]
fn output_failure_after_stdin_timeout_does_not_keep_process_alive() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sondera"))
        .args(["hook", "claude", "session-start"])
        .env("SONDERA_HOOK_BUDGET_SECS", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("hook process should start");

    drop(child.stdout.take());
    let _held_stdin = child.stdin.take().expect("stdin should stay open");

    let status = wait_for_exit(
        &mut child,
        "hook process remained alive after stdout failed",
    );
    assert_eq!(status.code(), Some(1));
}
