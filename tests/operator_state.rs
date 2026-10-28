//! In-place migration of the full known hosted state layout.

use openshell_kata::operator::{Prepare, prepare};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::{
        fs::{MetadataExt, PermissionsExt, symlink},
        net::UnixListener,
    },
    path::{Path, PathBuf},
};

const FIRST: &str = "kata-106875afd2ee0d519a03e601";
const SECOND: &str = "kata-0a438ccec38e0dfb546c4897";

fn permissions(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("fixture permissions");
}

fn file(path: &Path, bytes: &[u8], mode: u32) {
    fs::write(path, bytes).expect("fixture file");
    permissions(path, mode);
}

fn fixture(root: &Path) -> Prepare {
    let state = root.join("kata");
    fs::create_dir(&state).expect("state root");
    permissions(&state, 0o2770);
    fs::create_dir(state.join("registry")).expect("registry");
    permissions(&state.join("registry"), 0o700);
    file(
        &state
            .join("registry")
            .join(format!("{}.json", "a".repeat(64))),
        b"retained intent bytes",
        0o660,
    );
    for (name, mode) in [(FIRST, 0o2770), (SECOND, 0o2700)] {
        let folder = state.join(name);
        fs::create_dir(&folder).expect("sandbox folder");
        permissions(&folder, mode);
        file(
            &folder.join("client_key"),
            b"private client key fixture",
            0o660,
        );
        file(&folder.join("host_key"), b"private host key fixture", 0o660);
        file(
            &folder.join("client_key.pub"),
            b"public client key fixture",
            0o664,
        );
        file(
            &folder.join("host_key.pub"),
            b"public host key fixture",
            0o644,
        );
        file(&folder.join("known_hosts"), b"pinned host fixture", 0o660);
        file(&state.join(format!("{name}.lock")), b"", 0o644);
    }
    // Legacy key-only state is retained as-is, never given fabricated leases.
    file(
        &state.join(SECOND).join("metadata.json"),
        b"existing metadata bytes",
        0o660,
    );
    file(
        &state.join(SECOND).join("metadata.new"),
        b"legacy staged metadata bytes",
        0o660,
    );
    file(&state.join(".lock"), b"", 0o664);
    fs::create_dir(root.join("driver")).expect("driver mount");
    permissions(&root.join("driver"), 0o2777);
    fs::create_dir(root.join("trust")).expect("trust mount");
    permissions(&root.join("trust"), 0o2777);
    file(
        &root.join("trust/ca-bundle.pem"),
        b"old public bundle",
        0o644,
    );
    file(&root.join("system-ca"), b"system CA", 0o644);
    file(&root.join("platform-ca"), b"platform CA", 0o644);
    Prepare {
        state_dir: Some(state.clone()),
        driver_dir: Some(root.join("driver/private")),
        registry_dir: state.join("registry"),
        system_ca: root.join("system-ca"),
        platform_ca: root.join("platform-ca"),
        output: root.join("trust/private/ca-bundle.pem"),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    inode: u64,
    mode: u32,
    bytes: Option<Vec<u8>>,
}

fn inventory(root: &Path) -> BTreeMap<PathBuf, Snapshot> {
    fn visit(path: &Path, records: &mut BTreeMap<PathBuf, Snapshot>) {
        let metadata = fs::symlink_metadata(path).expect("snapshot metadata");
        records.insert(
            path.to_owned(),
            Snapshot {
                inode: metadata.ino(),
                mode: metadata.mode() & 0o7777,
                bytes: metadata
                    .is_file()
                    .then(|| fs::read(path).expect("fixture contents")),
            },
        );
        if metadata.is_dir() {
            for entry in fs::read_dir(path).expect("snapshot entries") {
                visit(&entry.expect("entry").path(), records);
            }
        }
    }
    let mut records = BTreeMap::new();
    visit(root, &mut records);
    records
}

#[test]
fn complete_migration_preserves_every_state_inode_byte_and_lock_identity() {
    let temporary = tempfile::tempdir().expect("fixture root");
    let input = fixture(temporary.path());
    let state = input.state_dir.as_ref().expect("state");
    let old = inventory(state);
    let old_ca = inventory(&temporary.path().join("trust/ca-bundle.pem"));
    let listener =
        UnixListener::bind(temporary.path().join("driver/driver.sock")).expect("old socket");
    let socket_inode = fs::symlink_metadata(temporary.path().join("driver/driver.sock"))
        .expect("socket")
        .ino();
    prepare(&input).expect("migrate whole state");
    let new = inventory(state);
    assert_eq!(old.len(), new.len(), "invented or removed state entries");
    for (path, before) in old {
        let after = new.get(&path).expect("same entry");
        assert_eq!(
            after.inode,
            before.inode,
            "replaced inode {}",
            path.display()
        );
        assert_eq!(
            after.bytes,
            before.bytes,
            "changed bytes {}",
            path.display()
        );
        assert_eq!(
            after.mode,
            if after.bytes.is_some() { 0o600 } else { 0o700 },
            "wrong repaired mode {}",
            path.display()
        );
    }
    assert!(
        !state.join(FIRST).join("metadata.json").exists(),
        "invented legacy lease metadata"
    );
    assert_eq!(
        fs::metadata(temporary.path().join("driver"))
            .expect("mount")
            .mode()
            & 0o7777,
        0o2777
    );
    assert_eq!(
        fs::metadata(temporary.path().join("trust"))
            .expect("mount")
            .mode()
            & 0o7777,
        0o2777
    );
    assert_eq!(
        inventory(&temporary.path().join("trust/ca-bundle.pem")),
        old_ca
    );
    assert_eq!(
        fs::symlink_metadata(temporary.path().join("driver/driver.sock"))
            .expect("old socket")
            .ino(),
        socket_inode
    );
    assert_eq!(
        fs::metadata(input.driver_dir.as_ref().expect("driver child"))
            .expect("private child")
            .mode()
            & 0o7777,
        0o700
    );
    drop(listener);
}

#[test]
fn any_unknown_or_unsafe_entry_prevents_all_state_mode_changes() {
    for invalid in [
        "unknown-root",
        "unknown-child",
        "symlink",
        "public-key-secret",
        "public-metadata",
        "public-write",
        "nonempty-lock",
        "oversized-key",
        "nested-directory",
        "bad-registry-name",
        "hardlink",
        "public-directory",
        "unknown-metadata-temporary",
    ] {
        let temporary = tempfile::tempdir().expect("fixture root");
        let input = fixture(temporary.path());
        let state = input.state_dir.as_ref().expect("state");
        let folder = state.join(FIRST);
        match invalid {
            "unknown-root" => file(&state.join("unexpected"), b"unknown", 0o600),
            "unknown-child" => file(&folder.join("unexpected"), b"unknown", 0o600),
            "symlink" => symlink(
                temporary.path().join("system-ca"),
                folder.join("metadata.json"),
            )
            .expect("link"),
            "public-key-secret" => permissions(&folder.join("client_key"), 0o644),
            "public-metadata" => permissions(&state.join(SECOND).join("metadata.json"), 0o644),
            "public-write" => permissions(&folder.join("client_key.pub"), 0o666),
            "nonempty-lock" => file(&state.join(".lock"), b"not empty", 0o600),
            "oversized-key" => fs::OpenOptions::new()
                .write(true)
                .open(folder.join("client_key"))
                .expect("key")
                .set_len(16 * 1024 + 1)
                .expect("oversize"),
            "nested-directory" => fs::create_dir(folder.join("deeper")).expect("nested"),
            "bad-registry-name" => file(&input.registry_dir.join("unknown.json"), b"intent", 0o600),
            "hardlink" => fs::hard_link(
                folder.join("client_key"),
                temporary.path().join("outside-hardlink"),
            )
            .expect("unexpected hardlink"),
            "public-directory" => permissions(&folder, 0o755),
            "unknown-metadata-temporary" => file(
                &folder.join(".metadata-00000000-0000-0000-0000-000000000000.tmp"),
                b"unknown staged state",
                0o600,
            ),
            _ => unreachable!("known fixture"),
        }
        let before = inventory(state);
        assert!(prepare(&input).is_err(), "accepted {invalid}");
        assert_eq!(inventory(state), before, "mutated state for {invalid}");
        assert!(!input.output.exists(), "published trust for {invalid}");
        assert!(
            !input.driver_dir.as_ref().expect("driver child").exists(),
            "created driver child for {invalid}"
        );
    }
}

#[test]
fn busy_stable_lock_blocks_migration_without_replacing_the_lock() {
    let temporary = tempfile::tempdir().expect("fixture root");
    let input = fixture(temporary.path());
    let state = input.state_dir.as_ref().expect("state");
    let before = inventory(state);
    let lock = fs::File::open(state.join(format!("{FIRST}.lock"))).expect("stable lock");
    lock.lock().expect("active owner");
    assert!(prepare(&input).is_err(), "migrated active state");
    assert_eq!(inventory(state), before);
    lock.unlock().expect("release lock");
    prepare(&input).expect("migrate quiesced state");
}

#[test]
fn full_state_registry_must_be_exact_child_and_never_creates_missing_state() {
    let temporary = tempfile::tempdir().expect("fixture root");
    let mut input = fixture(temporary.path());
    let state = input.state_dir.as_ref().expect("state").clone();
    let before = inventory(&state);
    input.registry_dir = temporary.path().join("other-registry");
    assert!(prepare(&input).is_err());
    assert_eq!(inventory(&state), before);
    input.state_dir = Some(temporary.path().join("fresh"));
    input.registry_dir = input
        .state_dir
        .as_ref()
        .expect("fresh state")
        .join("registry");
    prepare(&input).expect("prepare initial missing state");
    assert!(!input.state_dir.as_ref().expect("fresh state").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn full_state_rejects_foreign_owners_at_every_known_layout_level() {
    if rustix::process::geteuid().as_raw() != 0 {
        return;
    }
    for role in ["root", "sandbox", "key", "public-key", "lock", "registry"] {
        for owner in ["1:0", "0:1"] {
            let temporary = tempfile::tempdir().expect("fixture root");
            let input = fixture(temporary.path());
            let state = input.state_dir.as_ref().expect("state");
            let target = match role {
                "root" => state.clone(),
                "sandbox" => state.join(FIRST),
                "key" => state.join(FIRST).join("client_key"),
                "public-key" => state.join(FIRST).join("client_key.pub"),
                "lock" => state.join(format!("{FIRST}.lock")),
                "registry" => input.registry_dir.join(format!("{}.json", "a".repeat(64))),
                _ => unreachable!("known fixture role"),
            };
            assert!(
                std::process::Command::new("chown")
                    .arg(owner)
                    .arg(target)
                    .status()
                    .expect("foreign owner fixture")
                    .success()
            );
            let before = inventory(state);
            assert!(prepare(&input).is_err(), "accepted foreign {role} {owner}");
            assert_eq!(
                inventory(state),
                before,
                "mutated state after foreign {role} {owner}"
            );
            assert!(!input.output.exists());
        }
    }
}
