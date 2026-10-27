use super::*;

fn sh(script: &str) -> [&OsStr; 2] {
    [OsStr::new("-c"), OsStr::new(script)]
}

#[tokio::test(flavor = "current_thread")]
async fn returns_stdout_and_trimmed_stderr() {
    let out = output(Path::new("/bin/sh"), &sh("echo out; echo ' err ' >&2; exit 3"), b"").await.unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(out.stdout, b"out\n");
    assert_eq!(out.stderr, "err");
}

#[tokio::test(flavor = "current_thread")]
async fn passes_input_on_stdin() {
    let stdout = run(Path::new("/bin/sh"), &sh("cat"), b"hello").await.unwrap();
    assert_eq!(stdout, b"hello");
}

#[tokio::test(flavor = "current_thread")]
async fn nonzero_exit_is_failed() {
    let err = run(Path::new("/bin/sh"), &sh("echo bad >&2; exit 2"), b"").await.unwrap_err();
    assert!(matches!(&err, CommandError::Failed { stderr, .. } if stderr == "bad"), "{err:?}");
    assert_eq!(err.to_string(), "/bin/sh failed (exit status: 2): bad");
}

#[tokio::test(flavor = "current_thread")]
async fn missing_program_is_not_found() {
    let err = run(Path::new("/nonexistent/prog"), &[], b"").await.unwrap_err();
    assert!(matches!(&err, CommandError::NotFound { path } if path == Path::new("/nonexistent/prog")));
    assert_eq!(err.to_string(), "/nonexistent/prog not found");
}

