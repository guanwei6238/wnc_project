use super::*;

fn dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("wnc-gw-sink-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    dir
}

#[test]
fn appends_lines_to_a_file_only_its_group_can_read() {
    let dir = dir("lines");
    let mut sink = Sink::open(&dir, "flows").unwrap();
    sink.write(b"{\"a\":1}\n").unwrap();
    sink.write(b"").unwrap();
    sink.write(b"{\"a\":2}\n").unwrap();
    assert_eq!(fs::read_to_string(dir.join("flows.jsonl")).unwrap(), "{\"a\":1}\n{\"a\":2}\n");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(fs::metadata(dir.join("flows.jsonl")).unwrap().permissions().mode() & 0o777, 0o640);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn rotates_at_the_size_limit_and_keeps_one_old_file() {
    let dir = dir("rotate");
    let mut sink = Sink::open_with(&dir, "f", 100).unwrap();
    for _ in 0..12 {
        sink.write(b"{\"ts_ms\":1,\"feature\":\"f\",\"a\":1}\n").unwrap();
    }
    let old = fs::metadata(dir.join("f.jsonl.1")).unwrap().len();
    let new = fs::metadata(dir.join("f.jsonl")).unwrap().len();
    assert!(old >= 100, "{old}");
    assert!(new < 100, "{new}");
    fs::remove_dir_all(&dir).unwrap();
}
