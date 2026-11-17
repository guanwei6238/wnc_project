use super::*;

#[test]
fn backend_round_trips() {
    for backend in [TrustBackend::Tc, TrustBackend::CtMark] {
        assert_eq!(backend.to_string().parse::<TrustBackend>(), Ok(backend));
    }
}

#[test]
fn backend_defaults_to_tc() {
    assert_eq!(TrustBackend::default(), TrustBackend::Tc);
}

#[test]
fn rejects_unknown_backend() {
    assert_eq!(
        "ct_mark".parse::<TrustBackend>().unwrap_err().to_string(),
        "invalid trust backend \"ct_mark\" (expected \"tc\" or \"ctmark\")"
    );
}
