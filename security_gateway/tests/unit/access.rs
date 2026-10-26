use super::*;

#[test]
fn root_owned_and_not_shared_has_no_writers() {
    assert_eq!(writers(0, 0, 0o100755, false), vec![]);
    assert_eq!(writers(0, 0, 0o040755, true), vec![]);
}

#[test]
fn non_root_owner_can_write() {
    assert_eq!(writers(1000, 1000, 0o100644, false), vec![Writer::User(1000)]);
}

#[test]
fn group_and_world_writable() {
    assert_eq!(writers(0, 50, 0o040775, true), vec![Writer::Group(50)]);
    assert_eq!(writers(0, 0, 0o100646, false), vec![Writer::Everyone]);
    assert_eq!(
        writers(1000, 1000, 0o100666, false),
        vec![Writer::User(1000), Writer::Group(1000), Writer::Everyone]
    );
}

#[test]
fn sticky_directory_only_counts_its_owner() {
    assert_eq!(writers(0, 0, 0o041777, true), vec![]);
    assert_eq!(writers(1000, 1000, 0o041777, true), vec![Writer::User(1000)]);
}

#[test]
fn sticky_bit_on_a_file_is_ignored() {
    assert_eq!(writers(0, 0, 0o101666, false), vec![Writer::Group(0), Writer::Everyone]);
}

const PASSWD_TEXT: &str = "root:x:0:0:root:/root:/bin/bash\nwnc:x:1000:1000:,,,:/home/wnc:/bin/bash\nbroken\n";

#[test]
fn looks_up_names() {
    assert_eq!(name_of(PASSWD_TEXT, 0), Some("root".into()));
    assert_eq!(name_of(PASSWD_TEXT, 1000), Some("wnc".into()));
    assert_eq!(name_of(PASSWD_TEXT, 1001), None);
    assert_eq!(name_of("staff:x:50:\n", 50), Some("staff".into()));
}

#[test]
fn finds_owner_of_file_and_directory() {
    let dir = std::env::temp_dir().join(format!("wnc-gw-access-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("tool");
    std::fs::write(&file, "").unwrap();
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o757)).unwrap();
    let link = dir.join("link");
    std::os::unix::fs::symlink(&file, &link).unwrap();
    let uid = std::fs::metadata(&file).unwrap().uid();
    let direct = non_root_writers(&file);
    let through_link = non_root_writers(&link);
    std::fs::remove_dir_all(&dir).unwrap();

    let direct = direct.unwrap();
    assert!(direct.contains(&Writable { path: dir.clone(), writer: Writer::Everyone }));
    if uid != 0 {
        assert!(direct.contains(&Writable { path: file.clone(), writer: Writer::User(uid) }));
        assert!(direct.contains(&Writable { path: dir.clone(), writer: Writer::User(uid) }));
    }
    let through_link = through_link.unwrap();
    for writable in &direct {
        assert!(through_link.contains(writable), "{writable:?} is missing when checking through a symlink");
    }
}

#[test]
fn missing_path_is_not_found() {
    let err = non_root_writers(Path::new("/nonexistent/tool")).unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::NotFound);
}
