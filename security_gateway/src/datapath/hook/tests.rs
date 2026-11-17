use super::*;

const NATIVE: XdpFeatures = XdpFeatures(1 | 2 | 4);
const NONE: XdpFeatures = XdpFeatures(0);

#[test]
fn default_policy_is_auto() {
    assert_eq!(XdpPolicy::default(), XdpPolicy::Auto);
}

#[test]
fn policy_round_trips() {
    for policy in [XdpPolicy::Auto, XdpPolicy::Off, XdpPolicy::Generic] {
        assert_eq!(policy.to_string().parse::<XdpPolicy>(), Ok(policy));
    }
}

#[test]
fn invalid_policy_is_rejected() {
    let err = "native".parse::<XdpPolicy>().unwrap_err();
    assert_eq!(err.to_string(), "invalid xdp setting \"native\" (expected \"auto\", \"off\" or \"generic\")");
}

#[test]
fn auto_uses_native_xdp_when_supported() {
    assert_eq!(core_hook(XdpPolicy::Auto, Some(NATIVE)), CoreHook::NativeXdp);
}

#[test]
fn auto_falls_back_to_tc() {
    assert_eq!(core_hook(XdpPolicy::Auto, Some(NONE)), CoreHook::Tc);
    assert_eq!(core_hook(XdpPolicy::Auto, Some(XdpFeatures(2))), CoreHook::Tc);
    assert_eq!(core_hook(XdpPolicy::Auto, None), CoreHook::Tc);
}

#[test]
fn off_always_uses_tc() {
    assert_eq!(core_hook(XdpPolicy::Off, Some(NATIVE)), CoreHook::Tc);
}

#[test]
fn generic_only_when_requested() {
    assert_eq!(core_hook(XdpPolicy::Generic, None), CoreHook::GenericXdp);
    assert_eq!(core_hook(XdpPolicy::Generic, Some(NATIVE)), CoreHook::GenericXdp);
}
