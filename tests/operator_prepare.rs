//! Startup registry permission restoration and private CA publication.

use openshell_kata::operator::{Prepare, prepare};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
};

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("test permissions");
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path)
        .expect("test metadata")
        .permissions()
        .mode()
        & 0o7777
}

fn fixture(root: &Path) -> Prepare {
    let registry = root.join("registry");
    fs::create_dir(&registry).expect("registry");
    chmod(&registry, 0o2770);
    fs::write(
        registry.join("one.json"),
        b"not interpreted by permission repair",
    )
    .expect("record");
    chmod(&registry.join("one.json"), 0o660);
    fs::write(root.join("system-ca"), b"PUBLIC SYSTEM CA").expect("system CA");
    fs::write(root.join("platform-ca"), b"PUBLIC PLATFORM CA").expect("platform CA");
    Prepare {
        registry_dir: registry,
        system_ca: root.join("system-ca"),
        platform_ca: root.join("platform-ca"),
        output: root.join("trust/private/ca-bundle.pem"),
    }
}

#[test]
fn restores_group_inherited_modes_without_reading_records_and_publishes_private_bundle() {
    let root = tempfile::tempdir().expect("test root");
    let input = fixture(root.path());
    fs::create_dir(root.path().join("trust")).expect("group volume");
    chmod(&root.path().join("trust"), 0o2775);
    prepare(&input).expect("prepare registry and trust");
    assert_eq!(mode(&input.registry_dir), 0o700);
    assert_eq!(mode(&input.registry_dir.join("one.json")), 0o600);
    assert_eq!(
        fs::read(&input.output).expect("CA bundle"),
        b"PUBLIC SYSTEM CA\nPUBLIC PLATFORM CA"
    );
    assert_eq!(mode(input.output.parent().expect("output parent")), 0o700);
    assert_eq!(mode(&input.output), 0o600);
    prepare(&input).expect("idempotent prepare");
}

#[test]
fn entire_registry_is_rejected_before_any_permissions_or_output_change() {
    for invalid in [
        "symlink",
        "directory",
        "public-record",
        "hardlink",
        "public-root",
    ] {
        let root = tempfile::tempdir().expect("test root");
        let input = fixture(root.path());
        fs::create_dir(root.path().join("trust")).expect("trust volume");
        let bad = input.registry_dir.join("two.json");
        let outside = root.path().join("outside");
        match invalid {
            "symlink" => symlink(input.registry_dir.join("one.json"), &bad).expect("symlink"),
            "directory" => fs::create_dir(&bad).expect("nested directory"),
            "public-record" => {
                fs::write(&bad, b"record").expect("public record");
                chmod(&bad, 0o664);
            }
            "hardlink" => {
                fs::write(&outside, b"outside").expect("outside");
                chmod(&outside, 0o660);
                fs::hard_link(&outside, &bad).expect("hardlink");
            }
            "public-root" => chmod(&input.registry_dir, 0o2775),
            _ => unreachable!("known fixture"),
        }
        let old_root = mode(&input.registry_dir);
        let old_record = mode(&input.registry_dir.join("one.json"));
        assert!(prepare(&input).is_err(), "accepted {invalid}");
        assert_eq!(
            mode(&input.registry_dir),
            old_root,
            "changed root for {invalid}"
        );
        assert_eq!(
            mode(&input.registry_dir.join("one.json")),
            old_record,
            "changed valid record for {invalid}"
        );
        assert!(!input.output.exists(), "published output for {invalid}");
        if outside.exists() {
            assert_eq!(mode(&outside), 0o660);
        }
    }
}

#[test]
fn missing_registry_is_preserved_and_trusted_projected_ca_links_are_supported() {
    let root = tempfile::tempdir().expect("test root");
    let mut input = fixture(root.path());
    fs::remove_dir_all(&input.registry_dir).expect("remove initial registry");
    fs::create_dir(root.path().join("trust")).expect("trust volume");
    symlink(&input.platform_ca, root.path().join("projected-ca")).expect("projected CA link");
    input.platform_ca = root.path().join("projected-ca");
    prepare(&input).expect("prepare fresh volume");
    assert!(
        !input.registry_dir.exists(),
        "created registry during repair"
    );
    assert!(input.output.is_file());
}

#[test]
fn rejects_unsafe_output_or_ca_before_repairing_registry() {
    for invalid in [
        "output-parent-link",
        "public-output-parent",
        "output-link",
        "oversized-ca",
        "directory-ca",
    ] {
        let root = tempfile::tempdir().expect("test root");
        let mut input = fixture(root.path());
        fs::create_dir(root.path().join("trust")).expect("trust volume");
        let private = root.path().join("trust/private");
        match invalid {
            "output-parent-link" => {
                fs::create_dir(root.path().join("outside")).expect("outside");
                symlink(root.path().join("outside"), &private).expect("parent link");
            }
            "public-output-parent" => {
                fs::create_dir(&private).expect("public directory");
                chmod(&private, 0o755);
            }
            "output-link" => {
                fs::create_dir(&private).expect("private directory");
                chmod(&private, 0o700);
                symlink(&input.system_ca, &input.output).expect("output link");
            }
            "oversized-ca" => {
                fs::File::options()
                    .write(true)
                    .open(&input.system_ca)
                    .expect("system CA")
                    .set_len(2 * 1024 * 1024 + 1)
                    .expect("oversized CA");
            }
            "directory-ca" => input.system_ca = root.path().to_owned(),
            _ => unreachable!("known fixture"),
        }
        assert!(prepare(&input).is_err(), "accepted {invalid}");
        assert_eq!(
            mode(&input.registry_dir),
            0o2770,
            "changed root for {invalid}"
        );
        assert_eq!(
            mode(&input.registry_dir.join("one.json")),
            0o660,
            "changed record for {invalid}"
        );
    }
}

#[test]
fn rejects_symlink_registry_root_without_changing_target() {
    let root = tempfile::tempdir().expect("test root");
    let mut input = fixture(root.path());
    let actual = input.registry_dir.clone();
    let link = root.path().join("registry-link");
    symlink(&actual, &link).expect("registry link");
    input.registry_dir = link;
    assert!(prepare(&input).is_err());
    assert_eq!(mode(&actual), 0o2770);
}

#[test]
fn relative_paths_are_rejected_before_any_changes() {
    let root = tempfile::tempdir().expect("test root");
    let mut input = fixture(root.path());
    input.output = PathBuf::from("relative/bundle");
    assert!(prepare(&input).is_err());
    assert_eq!(mode(&input.registry_dir), 0o2770);
}

#[cfg(target_os = "linux")]
#[test]
fn rejects_foreign_registry_uid_and_gid_before_any_mode_changes() {
    // The real Linux container gate runs as root and can construct foreign
    // ownership fixtures. Ordinary developer sessions retain the other tests.
    if rustix::process::geteuid().as_raw() != 0 {
        return;
    }
    for invalid in ["root-uid", "root-gid", "record-uid", "record-gid"] {
        let root = tempfile::tempdir().expect("test root");
        let input = fixture(root.path());
        fs::create_dir(root.path().join("trust")).expect("trust volume");
        let target = if invalid.starts_with("root-") {
            input.registry_dir.clone()
        } else {
            input.registry_dir.join("one.json")
        };
        let owner = if invalid.ends_with("uid") {
            "1:0"
        } else {
            "0:1"
        };
        assert!(
            std::process::Command::new("chown")
                .arg(owner)
                .arg(&target)
                .status()
                .expect("foreign ownership fixture")
                .success()
        );
        let old_root = mode(&input.registry_dir);
        let old_record = mode(&input.registry_dir.join("one.json"));
        assert!(prepare(&input).is_err(), "accepted {invalid}");
        assert_eq!(mode(&input.registry_dir), old_root);
        assert_eq!(mode(&input.registry_dir.join("one.json")), old_record);
        assert!(!input.output.exists());
    }
}
