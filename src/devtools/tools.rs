use super::local::{Local, require_success, run};
use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::PermissionsExt,
    path::{Component, Path},
    time::Duration,
};

const VERSION: &str = "v0.1.6";
type Archive = (&'static str, &'static str, &'static str);
fn archives() -> Result<[Archive; 2]> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok([
            (
                "openshell",
                "aarch64-apple-darwin",
                "334e9cf24994a5bfd34691e9835920da15f5ef224cc96be0d4751eadfa279897",
            ),
            (
                "openshell-gateway",
                "aarch64-apple-darwin",
                "8313480f7d00264fc6c8eaad6e522736b20be97bed6a8f309c08fcb10e3c617b",
            ),
        ]),
        ("linux", "x86_64") => Ok([
            (
                "openshell",
                "x86_64-unknown-linux-musl",
                "2951c67366f3e3584ed9cec8d49b9f0b0eefc8cacea8b0582ac164590492f136",
            ),
            (
                "openshell-gateway",
                "x86_64-unknown-linux-gnu",
                "811265a55993beb333905a5b560764a40aa9177250171f711dce8ba820f7eff8",
            ),
        ]),
        ("linux", "aarch64") => Ok([
            (
                "openshell",
                "aarch64-unknown-linux-musl",
                "259452a6065c4f76e71884b84e8696cc0fec2f8a832891d333f268ca7bb55a21",
            ),
            (
                "openshell-gateway",
                "aarch64-unknown-linux-gnu",
                "de7342457746829138cecbc21cc90a2d5d4c0ea22a362b976831ac3bbb0109d6",
            ),
        ]),
        _ => bail!("no qualified official tool archives for this host"),
    }
}
pub fn digest(path: &Path) -> Result<String> {
    let mut source = File::open(path)?;
    let mut hash = Sha256::new();
    let mut block = [0; 65536];
    loop {
        let count = source.read(&mut block)?;
        if count == 0 {
            break;
        }
        hash.update(&block[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
pub fn verify_protocol(root: &Path) -> Result<()> {
    let root = root.join("proto");
    let mut names = std::collections::BTreeSet::new();
    for line in std::fs::read_to_string(root.join("SHA256SUMS"))?.lines() {
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() != 2
            || parts[0].len() != 64
            || !parts[0].bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            bail!("invalid vendored protocol checksum entry");
        }
        let name = parts[1].trim_start_matches('*');
        if !names.insert(name.to_owned()) {
            bail!("duplicate vendored protocol checksum entry");
        }
        let mut components = Path::new(name).components();
        if !matches!(components.next(), Some(Component::Normal(_)))
            || components.next().is_some()
            || digest(&root.join(name))? != parts[0]
        {
            bail!("vendored protocol checksum mismatch: {name}");
        }
    }
    if names.is_empty() {
        bail!("vendored protocol checksum manifest is empty");
    }
    println!("Vendored OpenShell protocol checksums verified");
    Ok(())
}
pub async fn fetch(local: &Local) -> Result<()> {
    let destination = local.state.join("bin");
    std::fs::create_dir_all(&destination)?;
    for (binary, target, expected) in archives()? {
        let temporary = tempfile::tempdir_in(&local.state)?;
        let name = format!("{binary}-{target}.tar.gz");
        let path = temporary.path().join(&name);
        let url = format!("https://github.com/NVIDIA/OpenShell/releases/download/{VERSION}/{name}");
        require_success(
            run(
                local
                    .command("curl")?
                    .args([
                        "--fail",
                        "--location",
                        "--silent",
                        "--show-error",
                        "--proto",
                        "=https",
                        "--tlsv1.2",
                        "--max-time",
                        "120",
                        "--max-filesize",
                        "536870912",
                        "--output",
                    ])
                    .arg(&path)
                    .arg(url),
                Duration::from_secs(125),
            )
            .await?,
        )?;
        if digest(&path)? != expected {
            bail!("official archive checksum mismatch: {name}");
        }
        let staged = temporary.path().join(binary);
        extract_binary(File::open(path)?, binary, &staged)?;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))?;
        std::fs::rename(staged, destination.join(binary))?;
        println!("Installed verified {binary} {VERSION}");
    }
    Ok(())
}
fn extract_binary(source: impl Read, binary: &str, destination: &Path) -> Result<()> {
    let mut archive = tar::Archive::new(GzDecoder::new(source));
    let mut found = false;
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.path()?.as_ref() != Path::new(binary) {
            continue;
        }
        if found || !entry.header().entry_type().is_file() || entry.size() > 512 * 1024 * 1024 {
            bail!("invalid official binary member");
        }
        let mut output = File::create(destination)?;
        std::io::copy(&mut entry, &mut output).context("extracting verified official binary")?;
        output.flush()?;
        found = true;
    }
    if !found {
        bail!("official archive is missing binary member");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn package(entries: &[(&str, bool)]) -> Result<Vec<u8>> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        let mut archive = tar::Builder::new(encoder);
        for (name, symlink) in entries {
            let mut header = tar::Header::new_ustar();
            header.set_mode(0o755);
            if *symlink {
                header.set_entry_type(tar::EntryType::Symlink);
                header.set_size(0);
                header.set_link_name("/etc/passwd")?;
                header.set_cksum();
                archive.append_data(&mut header, name, std::io::empty())?;
            } else {
                header.set_entry_type(tar::EntryType::Regular);
                header.set_size(6);
                header.set_cksum();
                archive.append_data(&mut header, name, &b"binary"[..])?;
            }
        }
        Ok(archive.into_inner()?.finish()?)
    }
    #[test]
    fn extracts_only_exact_regular_member() -> Result<()> {
        let root = tempfile::tempdir()?;
        let destination = root.path().join("binary");
        let archive = package(&[("ignored", false), ("openshell", false)])?;
        extract_binary(&archive[..], "openshell", &destination)?;
        assert_eq!(std::fs::read(&destination)?, b"binary");
        assert!(!root.path().join("ignored").exists());
        Ok(())
    }
    #[test]
    fn rejects_missing_duplicate_and_link_members() -> Result<()> {
        let root = tempfile::tempdir()?;
        for entries in [
            vec![("other", false)],
            vec![("openshell", false), ("openshell", false)],
            vec![("openshell", true)],
        ] {
            let archive = package(&entries)?;
            assert!(
                extract_binary(&archive[..], "openshell", &root.path().join("binary")).is_err()
            );
        }
        Ok(())
    }
    #[test]
    fn empty_and_duplicate_manifests_are_rejected() -> Result<()> {
        let root = tempfile::tempdir()?;
        let proto = root.path().join("proto");
        std::fs::create_dir(&proto)?;
        std::fs::write(proto.join("SHA256SUMS"), "")?;
        assert!(verify_protocol(root.path()).is_err());
        std::fs::write(proto.join("test.proto"), "pinned")?;
        let entry = format!("{}  test.proto\n", digest(&proto.join("test.proto"))?);
        std::fs::write(proto.join("SHA256SUMS"), entry.repeat(2))?;
        assert!(verify_protocol(root.path()).is_err());
        Ok(())
    }
    #[test]
    fn verifies_pinned_content_and_rejects_changes() -> Result<()> {
        let root = tempfile::tempdir()?;
        let proto = root.path().join("proto");
        std::fs::create_dir(&proto)?;
        std::fs::write(proto.join("test.proto"), b"pinned")?;
        let expected = digest(&proto.join("test.proto"))?;
        std::fs::write(
            proto.join("SHA256SUMS"),
            format!("{expected}  test.proto\n"),
        )?;
        verify_protocol(root.path())?;
        std::fs::write(proto.join("test.proto"), b"changed")?;
        assert!(verify_protocol(root.path()).is_err());
        Ok(())
    }
}
