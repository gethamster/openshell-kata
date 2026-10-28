//! Build the pinned Rust eBPF object without changing the main Rust toolchain.
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};
const NIGHTLY: &str = "nightly-2026-10-27";
const LINKER_VERSION: &str = "0.12.0";
fn command(program: &str, args: &[&str]) -> Result<Output, Box<dyn std::error::Error>> {
    let output = Command::new(program).args(args).output()?;
    if !output.status.success() {
        return Err(format!(
            "{program} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output)
}
fn sha256(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let result = command(
        "sha256sum",
        &[path.to_str().ok_or("non-UTF8 artifact path")?],
    )?;
    let output = String::from_utf8(result.stdout)?;
    let digest = output
        .split_ascii_whitespace()
        .next()
        .ok_or("digest absent")?;
    if digest.len() != 64 || !digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid artifact digest".into());
    }
    Ok(digest.into())
}
fn linker() -> Result<(&'static str, &'static str), Box<dyn std::error::Error>> {
    match env::consts::ARCH {
        "x86_64" => Ok((
            "x86_64",
            "6789717c8cb6a2a5d920f3b6bfac2bd7efc00f6228ecd149108a99699a75c679",
        )),
        "aarch64" => Ok((
            "aarch64",
            "5e201e69dafac7af98f9788f1c68edd5ccc8fa0805093f899bf02bd2947b3935",
        )),
        _ => Err("the eBPF builder supports Linux x86_64 and aarch64 only".into()),
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::consts::OS != "linux" {
        return Err("build this object on Linux; regular adapter builds use stable Rust".into());
    }
    let arguments: Vec<_> = env::args().skip(1).collect();
    if arguments.len() != 2 || arguments[0] != "--output-dir" {
        return Err(
            "usage: build-hosted-fence --output-dir PATH (run from repository root)".into(),
        );
    }
    let output_dir = PathBuf::from(&arguments[1]);
    fs::create_dir_all(&output_dir)?;
    let work = env::var_os("OPENSHELL_KATA_FENCE_BUILD_DIR")
        .map_or_else(|| PathBuf::from(".local/fence-build"), PathBuf::from);
    fs::create_dir_all(&work)?;
    let work = fs::canonicalize(work)?;
    let tools = work.join("tools");
    fs::create_dir_all(&tools)?;
    let (architecture, expected) = linker()?;
    let archive = tools.join("bpf-linker.tar.zst");
    let url = format!(
        "https://github.com/aya-rs/bpf-linker/releases/download/v{LINKER_VERSION}/bpf-linker-{architecture}-unknown-linux-musl.tar.zst"
    );
    command(
        "curl",
        &[
            "--proto",
            "=https",
            "--tlsv1.2",
            "--fail",
            "--show-error",
            "--location",
            &url,
            "--output",
            archive.to_str().ok_or("non-UTF8 build path")?,
        ],
    )?;
    if sha256(&archive)? != expected {
        return Err("official bpf-linker archive SHA-256 mismatch".into());
    }
    command(
        "tar",
        &[
            "--zstd",
            "-xf",
            archive.to_str().ok_or("non-UTF8 build path")?,
            "-C",
            tools.to_str().ok_or("non-UTF8 build path")?,
        ],
    )?;
    command(
        "rustup",
        &[
            "toolchain",
            "install",
            NIGHTLY,
            "--component",
            "rust-src",
            "--profile",
            "minimal",
        ],
    )?;
    let target = work.join("target");
    let paths = env::join_paths(
        std::iter::once(tools.clone())
            .chain(env::split_paths(&env::var_os("PATH").unwrap_or_default())),
    )?;
    let result = Command::new("cargo")
        .env("PATH", paths)
        .env("CARGO_TARGET_DIR", &target)
        .env("CARGO_INCREMENTAL", "0")
        .args([
            &format!("+{NIGHTLY}"),
            "build",
            "--locked",
            "--manifest-path",
            "fence-ebpf/Cargo.toml",
            "--release",
            "--target",
            "bpfel-unknown-none",
            "-Z",
            "build-std=core",
        ])
        .status()?;
    if !result.success() {
        return Err("the Rust eBPF build failed".into());
    }
    let artifact = output_dir.join("openshell-kata-fence.o");
    fs::copy(
        target.join("bpfel-unknown-none/release/openshell-kata-fence"),
        &artifact,
    )?;
    let digest = sha256(&artifact)?;
    fs::write(
        output_dir.join("openshell-kata-fence.o.sha256"),
        format!("{digest}  openshell-kata-fence.o\n"),
    )?;
    fs::write(
        output_dir.join("build-inputs.txt"),
        format!(
            "rust_toolchain={NIGHTLY}\nbpf_linker_version={LINKER_VERSION}\nbpf_linker_archive_sha256={expected}\nobject_sha256={digest}\n"
        ),
    )?;
    println!("{}", artifact.display());
    Ok(())
}
