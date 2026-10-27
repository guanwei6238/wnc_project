use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use super::*;

fn options(dir: &Path, path: PathBuf, ready_timeout: Duration) -> Options {
    Options {
        path,
        config: "/etc/suricata/suricata.yaml".into(),
        queue: QueueRange::default(),
        ready_timeout,
        stop_timeout: Duration::from_secs(5),
        fail_open: true,
        runtime_dir: dir.join("run"),
        log_dir: dir.join("log"),
    }
}

#[test]
fn passes_config_queue_and_own_directories() {
    let mut options = options(Path::new("/x"), "/usr/bin/suricata".into(), Duration::from_secs(1));
    assert_eq!(
        suricata_args(&options),
        [
            "-c",
            "/etc/suricata/suricata.yaml",
            "-q",
            "0",
            "-l",
            "/x/log",
            "--set",
            "unix-command.filename=/x/run/suricata.sock",
            "--set",
            "nfq.fail-open=yes",
            "--set",
            "detect.delayed-detect=no",
            "--set",
            "coredump.max-dump=0",
        ]
        .map(OsString::from)
    );
    options.queue = "0-3".parse().unwrap();
    options.fail_open = false;
    let args = suricata_args(&options);
    assert_eq!((&args[3], &args[9]), (&OsString::from("0:3"), &OsString::from("nfq.fail-open=no")));
}

#[test]
fn recognizes_ready_notification() {
    assert!(is_ready(b"READY=1"));
    assert!(is_ready(b"STATUS=loading\nREADY=1\n"));
    assert!(!is_ready(b"READY=0"));
    assert!(!is_ready(b"STATUS=READY=1"));
    assert!(!is_ready(b"\xffREADY=1"));
}

#[test]
fn classifies_suricata_output() {
    assert_eq!(classify("E: nfq: nfq_create_queue failed"), (Level::Error, "nfq: nfq_create_queue failed"));
    assert_eq!(
        classify("Error: conf-yaml-loader: failed to open file"),
        (Level::Error, "conf-yaml-loader: failed to open file")
    );
    assert_eq!(classify("W: detect: No rule files match"), (Level::Warn, "detect: No rule files match"));
    assert_eq!(classify("i: suricata: Engine started."), (Level::Info, "suricata: Engine started."));
    assert_eq!(classify("Notice: something"), (Level::Info, "Notice: something"));
    assert_eq!(classify("plain line"), (Level::Info, "plain line"));
}

#[test]
fn backoff_doubles_up_to_a_minute_and_resets() {
    let mut backoff = Backoff::new();
    let delays: Vec<u64> = (0..9).map(|_| backoff.next_delay().as_secs()).collect();
    assert_eq!(delays, [1, 2, 4, 8, 16, 32, 60, 60, 60]);
    backoff.reset();
    assert_eq!(backoff.next_delay(), Duration::from_secs(1));
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("wnc-gw-spawned-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn script(&self, body: &str) -> PathBuf {
        let path = self.0.join("fake-suricata");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn next(suricata: &mut SpawnedSuricata) -> Event {
    tokio::time::timeout(Duration::from_secs(10), suricata.next_event())
        .await
        .expect("an event within 10 seconds")
        .expect("supervision still running")
}

#[tokio::test(flavor = "current_thread")]
async fn runs_the_command_with_notify_socket() {
    let scratch = Scratch::new("args");
    let out = scratch.0.join("out");
    let script = scratch.script(&format!(
        "echo \"$@\" > {0}; echo \"$NOTIFY_SOCKET\" >> {0}; pwd >> {0}; exit 3",
        out.display()
    ));
    let mut suricata = SpawnedSuricata::start(options(&scratch.0, script, Duration::from_secs(10))).unwrap();
    let event = next(&mut suricata).await;
    suricata.stop().await;
    assert!(matches!(event, Event::Stopped { exit: Some(Exit::Code(3)), was_ready: false, .. }), "{event:?}");
    let run = scratch.0.join("run");
    assert_eq!(
        std::fs::read_to_string(&out).unwrap(),
        format!(
            "-c /etc/suricata/suricata.yaml -q 0 -l {0} --set unix-command.filename={1} --set nfq.fail-open=yes \
             --set detect.delayed-detect=no --set coredump.max-dump=0\n{2}\n{0}\n",
            scratch.0.join("log").display(),
            run.join("suricata.sock").display(),
            run.join("notify.sock").display()
        )
    );
}

#[tokio::test(flavor = "current_thread")]
async fn restarts_after_an_exit() {
    let scratch = Scratch::new("restart");
    let script = scratch.script("exit 1");
    let mut suricata = SpawnedSuricata::start(options(&scratch.0, script, Duration::from_secs(10))).unwrap();
    let first = next(&mut suricata).await;
    suricata.allow_restart();
    let second = next(&mut suricata).await;
    suricata.stop().await;
    for event in [first, second] {
        assert!(matches!(event, Event::Stopped { exit: Some(Exit::Code(1)), .. }), "{event:?}");
    }
}

#[tokio::test(flavor = "current_thread")]
async fn waits_for_permission_before_restarting() {
    let scratch = Scratch::new("gate");
    let runs = scratch.0.join("runs");
    let script = scratch.script(&format!("echo run >> {}; exit 1", runs.display()));
    let mut suricata = SpawnedSuricata::start(options(&scratch.0, script, Duration::from_secs(10))).unwrap();
    next(&mut suricata).await;
    let waited = tokio::time::timeout(Duration::from_millis(1500), suricata.next_event()).await;
    assert!(waited.is_err(), "restarted without permission: {waited:?}");
    assert_eq!(std::fs::read_to_string(&runs).unwrap().lines().count(), 1);
    suricata.allow_restart();
    next(&mut suricata).await;
    suricata.stop().await;
    assert_eq!(std::fs::read_to_string(&runs).unwrap().lines().count(), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn stops_while_waiting_for_permission() {
    let scratch = Scratch::new("gate-stop");
    let script = scratch.script("exit 1");
    let mut suricata = SpawnedSuricata::start(options(&scratch.0, script, Duration::from_secs(10))).unwrap();
    next(&mut suricata).await;
    let started = Instant::now();
    suricata.stop().await;
    assert!(started.elapsed() < Duration::from_secs(1), "stopping took {:?}", started.elapsed());
}

#[tokio::test(flavor = "current_thread")]
async fn stops_a_start_that_never_becomes_ready() {
    let scratch = Scratch::new("timeout");
    let script = scratch.script("exec sleep 30");
    let mut suricata = SpawnedSuricata::start(options(&scratch.0, script, Duration::from_millis(300))).unwrap();
    let event = next(&mut suricata).await;
    suricata.stop().await;
    assert!(
        matches!(event, Event::Stopped { exit: Some(Exit::Signal(libc::SIGTERM)), was_ready: false, .. }),
        "{event:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn waits_for_suricata_to_finish_stopping() {
    let scratch = Scratch::new("graceful");
    let mark = scratch.0.join("graceful");
    let script = scratch.script(&format!(
        "trap 'sleep 1; echo done > {}; exit 0' TERM; while :; do sleep 0.1; done",
        mark.display()
    ));
    let suricata = SpawnedSuricata::start(options(&scratch.0, script, Duration::from_secs(10))).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let started = Instant::now();
    suricata.stop().await;
    let took = started.elapsed();
    assert!(mark.exists(), "suricata was killed before it finished stopping");
    assert!(took >= Duration::from_secs(1) && took < Duration::from_secs(5), "stopping took {took:?}");
}

#[tokio::test(flavor = "current_thread")]
async fn kills_suricata_after_stop_timeout() {
    let scratch = Scratch::new("kill");
    let script = scratch.script("trap '' TERM; echo $$ > pid; while :; do sleep 0.1; done");
    let mut options = options(&scratch.0, script, Duration::from_secs(10));
    options.stop_timeout = Duration::from_secs(1);
    let suricata = SpawnedSuricata::start(options).unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let started = Instant::now();
    suricata.stop().await;
    let took = started.elapsed();
    assert!(took >= Duration::from_secs(1) && took < Duration::from_secs(3), "stopping took {took:?}");
    let pid = std::fs::read_to_string(scratch.0.join("log/pid")).unwrap();
    assert!(!Path::new(&format!("/proc/{}", pid.trim())).exists(), "process {} is still running", pid.trim());
}

#[tokio::test(flavor = "current_thread")]
async fn reports_ready_and_stops_on_request() {
    if std::process::Command::new("python3").arg("-c").arg("").status().is_err() {
        eprintln!("skipped: python3 is needed to send the readiness notification");
        return;
    }
    let scratch = Scratch::new("ready");
    let script = scratch.script(
        "exec python3 -c 'import os, socket, time\n\
         s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)\n\
         s.sendto(b\"READY=1\", os.environ[\"NOTIFY_SOCKET\"])\n\
         time.sleep(30)'",
    );
    let mut suricata = SpawnedSuricata::start(options(&scratch.0, script, Duration::from_secs(10))).unwrap();
    let event = next(&mut suricata).await;
    let Event::Ready { pid, .. } = event else {
        panic!("expected ready, got {event:?}");
    };
    let started = Instant::now();
    suricata.stop().await;
    assert!(started.elapsed() < Duration::from_secs(5), "stopping took {:?}", started.elapsed());
    assert!(!Path::new(&format!("/proc/{pid}")).exists(), "process {pid} is still running");
}
