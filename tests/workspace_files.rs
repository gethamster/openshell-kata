//! Guest workspace file protocol and confinement regressions.

use openshell_kata::workspace::{RemoveOptions, Workspace};
use sha2::{Digest, Sha256};
use std::{fs, io::Cursor, os::unix::fs::symlink};

fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut framed = Vec::new();
    for chunk in bytes.chunks(65536) {
        framed.extend_from_slice(&(chunk.len() as u32).to_be_bytes());
        framed.extend_from_slice(chunk);
    }
    framed.extend_from_slice(&[0; 4]);
    framed.extend_from_slice(&Sha256::digest(bytes));
    framed
}

#[test]
fn framed_files_round_trip_binary_empty_and_multiple_chunks() {
    let temporary = tempfile::tempdir().expect("workspace");
    let workspace = Workspace::open(temporary.path()).expect("open workspace");
    for data in [
        Vec::new(),
        b"binary\0payload\xff".to_vec(),
        vec![42; 150000],
    ] {
        workspace
            .write("/sandbox/nested/file", Cursor::new(frame(&data)))
            .expect("write framed file");
        let mut output = Vec::new();
        assert!(
            workspace
                .read("/sandbox/nested/file", &mut output)
                .expect("read")
        );
        assert_eq!(output, data);
        assert_eq!(
            fs::read_dir(temporary.path().join("nested"))
                .expect("entries")
                .count(),
            1
        );
    }
    assert!(
        !workspace
            .read("/sandbox/missing", Vec::new())
            .expect("missing")
    );
}

#[test]
fn invalid_or_incomplete_frames_preserve_existing_file_and_remove_staging() {
    let temporary = tempfile::tempdir().expect("workspace");
    fs::write(temporary.path().join("file"), b"original").expect("seed file");
    let workspace = Workspace::open(temporary.path()).expect("open workspace");
    let valid = frame(b"replacement");
    let mut bad_digest = valid.clone();
    *bad_digest.last_mut().expect("digest") ^= 1;
    let mut trailing = valid.clone();
    trailing.push(1);
    let oversized = 65537_u32.to_be_bytes().to_vec();
    for bytes in [
        Vec::new(),
        valid[..8].to_vec(),
        bad_digest,
        trailing,
        oversized,
    ] {
        assert!(
            workspace
                .write("/sandbox/file", Cursor::new(bytes))
                .is_err()
        );
        assert_eq!(
            fs::read(temporary.path().join("file")).expect("original"),
            b"original"
        );
        assert_eq!(fs::read_dir(temporary.path()).expect("entries").count(), 1);
    }
}

#[test]
fn workspace_paths_and_symlink_parents_cannot_reach_outside_files() {
    let temporary = tempfile::tempdir().expect("workspace");
    let outside = tempfile::tempdir().expect("outside");
    fs::write(outside.path().join("canary"), b"outside").expect("canary");
    symlink(outside.path(), temporary.path().join("link")).expect("parent link");
    let workspace = Workspace::open(temporary.path()).expect("open workspace");
    for path in [
        "/sandbox/../canary",
        "/sandbox//canary",
        "/sandbox/./canary",
        "/etc/passwd",
        "/sandbox",
        "relative",
        "/sandbox/link/canary",
    ] {
        assert!(
            workspace.write(path, Cursor::new(frame(b"wrong"))).is_err(),
            "accepted {path}"
        );
        assert!(
            workspace.read(path, Vec::new()).is_err(),
            "accepted read {path}"
        );
        assert!(
            workspace.remove(path, RemoveOptions::default()).is_err(),
            "accepted removal {path}"
        );
    }
    assert_eq!(
        fs::read(outside.path().join("canary")).expect("canary"),
        b"outside"
    );
}

#[test]
fn read_rejects_symlink_and_atomic_write_replaces_link_without_following_it() {
    let temporary = tempfile::tempdir().expect("workspace");
    let outside = tempfile::NamedTempFile::new().expect("outside");
    fs::write(outside.path(), b"outside").expect("canary");
    symlink(outside.path(), temporary.path().join("link")).expect("link");
    let workspace = Workspace::open(temporary.path()).expect("open workspace");
    assert!(workspace.read("/sandbox/link", Vec::new()).is_err());
    workspace
        .write("/sandbox/link", Cursor::new(frame(b"replacement")))
        .expect("replace link");
    assert_eq!(fs::read(outside.path()).expect("outside"), b"outside");
    assert_eq!(
        fs::read(temporary.path().join("link")).expect("replacement"),
        b"replacement"
    );
}

#[test]
fn recursive_remove_does_not_follow_links_and_force_controls_missing_paths() {
    let temporary = tempfile::tempdir().expect("workspace");
    let outside = tempfile::tempdir().expect("outside");
    fs::write(outside.path().join("canary"), b"outside").expect("canary");
    fs::create_dir(temporary.path().join("tree")).expect("tree");
    symlink(outside.path(), temporary.path().join("tree/link")).expect("link");
    let workspace = Workspace::open(temporary.path()).expect("open workspace");
    assert!(
        workspace
            .remove("/sandbox/tree", RemoveOptions::default())
            .is_err()
    );
    workspace
        .remove(
            "/sandbox/tree",
            RemoveOptions {
                recursive: true,
                force: false,
            },
        )
        .expect("remove tree");
    assert_eq!(
        fs::read(outside.path().join("canary")).expect("canary"),
        b"outside"
    );
    assert!(
        workspace
            .remove("/sandbox/absent", RemoveOptions::default())
            .is_err()
    );
    workspace
        .remove(
            "/sandbox/absent",
            RemoveOptions {
                force: true,
                recursive: false,
            },
        )
        .expect("force missing");
}

#[test]
fn retained_root_capability_survives_root_rename_without_writing_replacement() {
    let temporary = tempfile::tempdir().expect("parent");
    let root = temporary.path().join("root");
    let moved = temporary.path().join("moved");
    fs::create_dir(&root).expect("root");
    let workspace = Workspace::open(&root).expect("open workspace");
    fs::rename(&root, &moved).expect("move root");
    fs::create_dir(&root).expect("unrelated replacement");
    workspace
        .write("/sandbox/file", Cursor::new(frame(b"retained")))
        .expect("write through capability");
    assert_eq!(fs::read(moved.join("file")).expect("retained"), b"retained");
    assert_eq!(fs::read_dir(&root).expect("unrelated root").count(), 0);
}

#[test]
fn read_rejects_special_and_oversized_files_without_publishing_bytes() {
    let temporary = tempfile::tempdir().expect("workspace");
    let large = fs::File::create(temporary.path().join("large")).expect("sparse file");
    large
        .set_len(openshell_kata::workspace::MAX_FILE_BYTES + 1)
        .expect("sparse length");
    let listener =
        std::os::unix::net::UnixListener::bind(temporary.path().join("socket")).expect("socket");
    let workspace = Workspace::open(temporary.path()).expect("workspace capability");
    for path in ["/sandbox/large", "/sandbox/socket"] {
        let mut output = Vec::new();
        assert!(
            workspace.read(path, &mut output).is_err(),
            "accepted {path}"
        );
        assert!(output.is_empty(), "published bytes from {path}");
    }
    drop(listener);
}

#[test]
fn refuses_symlink_roots_and_relative_roots() {
    let temporary = tempfile::tempdir().expect("root parent");
    fs::create_dir(temporary.path().join("real")).expect("real root");
    symlink(temporary.path().join("real"), temporary.path().join("link")).expect("root link");
    assert!(Workspace::open(temporary.path().join("link")).is_err());
    assert!(Workspace::open("relative").is_err());
}
