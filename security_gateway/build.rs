use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const EBPF_PACKAGE: &str = "gw-ebpf";
const EBPF_TOOLCHAIN: &str = "nightly-2026-11-13";
const EBPF_TARGET: &str = "bpfel-unknown-none";

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo"));
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR is set by cargo"));
    println!("cargo::rerun-if-changed={}", manifest_dir.join(EBPF_PACKAGE).display());
    println!("cargo::rerun-if-changed={}", manifest_dir.join("Cargo.lock").display());

    // 另外的 target 目錄：和外層的 cargo 共用會互相鎖住
    let target_dir = out_dir.join("ebpf-target");
    let output = Command::new("rustup")
        .args(["run", EBPF_TOOLCHAIN, "cargo", "build", "--quiet", "--release"])
        .args(["--package", EBPF_PACKAGE, "--target", EBPF_TARGET, "-Z", "build-std=core"])
        .arg("--target-dir")
        .arg(&target_dir)
        .current_dir(&manifest_dir)
        // 外層 cargo 設的 RUSTC 指向 stable，留著會讓 nightly 的 cargo 用錯編譯器
        .env_remove("RUSTC")
        .env_remove("RUSTC_WRAPPER")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .env("CARGO_ENCODED_RUSTFLAGS", "-Cdebuginfo=2\x1f-Clink-arg=--btf")
        .output();
    let output = match output {
        Ok(output) => output,
        Err(e) => panic!("cannot run rustup to build {EBPF_PACKAGE}: {e}"),
    };
    if !output.status.success() {
        panic!(
            "building {EBPF_PACKAGE} failed ({}); it needs the {EBPF_TOOLCHAIN} toolchain with rust-src and \
             bpf-linker in PATH:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let built = target_dir.join(EBPF_TARGET).join("release").join(EBPF_PACKAGE);
    if let Err(e) = fs::copy(&built, out_dir.join(EBPF_PACKAGE)) {
        panic!("cannot copy {}: {e}", built.display());
    }
}
