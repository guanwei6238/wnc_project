use std::mem::offset_of;

use super::*;

#[test]
fn query_attr_matches_the_kernel_layout() {
    assert_eq!(size_of::<QueryAttr>(), 64);
    assert_eq!(offset_of!(QueryAttr, attach_type), 4);
    assert_eq!(offset_of!(QueryAttr, query_flags), 8);
    assert_eq!(offset_of!(QueryAttr, attach_flags), 12);
    assert_eq!(offset_of!(QueryAttr, prog_ids), 16);
    assert_eq!(offset_of!(QueryAttr, prog_cnt), 24);
    assert_eq!(offset_of!(QueryAttr, prog_attach_flags), 32);
    assert_eq!(offset_of!(QueryAttr, link_ids), 40);
    assert_eq!(offset_of!(QueryAttr, link_attach_flags), 48);
    assert_eq!(offset_of!(QueryAttr, revision), 56);
}

#[test]
fn query_errors_are_classified() {
    let error = |errno| query_error(io::Error::from_raw_os_error(errno), 7);
    assert!(matches!(error(libc::EPERM), TcxQueryError::NotPermitted));
    assert!(matches!(error(libc::EACCES), TcxQueryError::NotPermitted));
    assert!(matches!(error(libc::EINVAL), TcxQueryError::Unsupported));
    assert!(matches!(error(libc::ENODEV), TcxQueryError::NoDevice(7)));
    assert!(matches!(error(libc::EFAULT), TcxQueryError::Io(_)));
}

#[test]
fn error_chain_skips_causes_already_in_the_message() {
    #[derive(Debug, thiserror::Error)]
    #[error("outer: {0}")]
    struct Repeats(#[source] io::Error);
    #[derive(Debug, thiserror::Error)]
    #[error("outer")]
    struct Hides(#[source] io::Error);
    let inner = || io::Error::other("inner");
    assert_eq!(error_chain(&Repeats(inner())), "outer: inner");
    assert_eq!(error_chain(&Hides(inner())), "outer: inner");
}
