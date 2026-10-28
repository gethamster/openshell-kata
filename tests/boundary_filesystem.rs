use openshell_kata::boundary::filesystem::{FilesystemPolicy, ImportId, ImportStore};
use std::io::{Cursor, Read};

fn archive(entries: &[(&str, tar::EntryType, &[u8])]) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut bytes);
        for (path, kind, data) in entries {
            let mut header = tar::Header::new_ustar();
            // Raw path assignment lets tests build malicious names intentionally.
            header.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
            header.set_entry_type(*kind);
            header.set_size(data.len() as u64);
            header.set_mode(0o6777);
            header.set_cksum();
            builder.append(&header, *data).expect("append fixture");
        }
        builder.finish().expect("finish fixture");
    }
    bytes
}

#[test]
fn imports_and_exports_normalized_archive_atomically() {
    let root = openshell_kata::boundary::filesystem::private_transfer_directory().expect("root");
    let store = ImportStore::open(root.path()).expect("store");
    let input = archive(&[
        ("./src/", tar::EntryType::Directory, b""),
        ("./src/main.rs", tar::EntryType::Regular, b"fn main() {}"),
    ]);
    let id = store
        .import_tar(Cursor::new(input), &FilesystemPolicy::default())
        .expect("import");
    let mut output = Vec::new();
    store
        .export_tar(&id, &mut output, &FilesystemPolicy::default())
        .expect("export");
    let mut tar = tar::Archive::new(Cursor::new(output));
    let mut entries = tar.entries().expect("entries");
    assert_eq!(
        entries
            .next()
            .expect("directory")
            .expect("valid")
            .path()
            .expect("path")
            .to_str(),
        Some("src")
    );
    let mut file = entries.next().expect("file").expect("valid");
    assert_eq!(file.header().mode().expect("mode"), 0o700);
    assert_eq!(file.header().uid().expect("uid"), 0);
    let mut body = String::new();
    file.read_to_string(&mut body).expect("body");
    assert_eq!(body, "fn main() {}");
    assert_eq!(std::fs::read_dir(root.path()).expect("entries").count(), 1);
}

#[cfg(unix)]
#[test]
fn publication_sync_remains_bound_to_an_opened_directory_after_rename() {
    let parent =
        openshell_kata::boundary::filesystem::private_transfer_directory().expect("private parent");
    let original = parent.path().join("original");
    let renamed = parent.path().join("renamed");
    std::fs::create_dir(&original).expect("store directory");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o700))
        .expect("private store");
    let store = ImportStore::open(&original).expect("open store capability");
    std::fs::rename(&original, &renamed).expect("rename opened store");
    std::fs::create_dir(&original).expect("unrelated replacement directory");

    let id = store
        .import_tar(
            Cursor::new(archive(&[("safe", tar::EntryType::Regular, b"source")])),
            &FilesystemPolicy::default(),
        )
        .expect("publish and sync using the retained directory capability");

    assert!(renamed.join(format!("{id}.tar")).is_file());
    assert_eq!(
        std::fs::read_dir(&original).expect("replacement").count(),
        0
    );
    store.remove(&id).expect("remove published transfer");
}

#[test]
fn rejects_traversal_links_devices_duplicate_and_conflicting_paths() {
    let root = openshell_kata::boundary::filesystem::private_transfer_directory().expect("root");
    let store = ImportStore::open(root.path()).expect("store");
    for path in [
        "../escape",
        "/escape",
        "src/../escape",
        "C:/escape",
        "src\\escape",
        "src//file",
    ] {
        assert!(
            store
                .import_tar(
                    Cursor::new(archive(&[(path, tar::EntryType::Regular, b"x")])),
                    &FilesystemPolicy::default()
                )
                .is_err(),
            "accepted {path}"
        );
    }
    for kind in [
        tar::EntryType::Symlink,
        tar::EntryType::Link,
        tar::EntryType::Fifo,
        tar::EntryType::Block,
        tar::EntryType::Char,
        tar::EntryType::GNUSparse,
        tar::EntryType::GNULongName,
        tar::EntryType::XHeader,
    ] {
        assert!(
            store
                .import_tar(
                    Cursor::new(archive(&[("entry", kind, b"")])),
                    &FilesystemPolicy::default()
                )
                .is_err()
        );
    }
    for items in [
        vec![
            ("a", tar::EntryType::Regular, b"x".as_slice()),
            ("a", tar::EntryType::Regular, b"y".as_slice()),
        ],
        vec![
            ("a", tar::EntryType::Regular, b"x".as_slice()),
            ("a/b", tar::EntryType::Regular, b"y".as_slice()),
        ],
        vec![
            ("a/b", tar::EntryType::Regular, b"x".as_slice()),
            ("a", tar::EntryType::Regular, b"y".as_slice()),
        ],
    ] {
        assert!(
            store
                .import_tar(Cursor::new(archive(&items)), &FilesystemPolicy::default())
                .is_err()
        );
    }
    assert_eq!(std::fs::read_dir(root.path()).expect("entries").count(), 0);
}

#[test]
fn quotas_and_truncation_publish_nothing() {
    let root = openshell_kata::boundary::filesystem::private_transfer_directory().expect("root");
    let store = ImportStore::open(root.path()).expect("store");
    let policy = FilesystemPolicy {
        transfer_max_bytes: 2,
        transfer_max_entries: 1,
        ..FilesystemPolicy::default()
    };
    assert!(
        store
            .import_tar(
                Cursor::new(archive(&[("big", tar::EntryType::Regular, b"abc")])),
                &policy
            )
            .is_err()
    );
    assert!(
        store
            .import_tar(
                Cursor::new(archive(&[
                    ("a", tar::EntryType::Regular, b"a"),
                    ("b", tar::EntryType::Regular, b"b")
                ])),
                &policy
            )
            .is_err()
    );
    let mut truncated = archive(&[("a", tar::EntryType::Regular, b"abc")]);
    truncated.truncate(513);
    assert!(
        store
            .import_tar(Cursor::new(truncated), &FilesystemPolicy::default())
            .is_err()
    );
    assert_eq!(std::fs::read_dir(root.path()).expect("entries").count(), 0);
}

#[test]
fn rejects_opaque_id_path_injection_and_tampered_artifacts() {
    assert!("../secrets".parse::<ImportId>().is_err());
    let root = openshell_kata::boundary::filesystem::private_transfer_directory().expect("root");
    let store = ImportStore::open(root.path()).expect("store");
    let id = store
        .import_tar(
            Cursor::new(archive(&[("safe", tar::EntryType::Regular, b"abc")])),
            &FilesystemPolicy::default(),
        )
        .expect("import");
    let target = root.path().join(format!("{id}.tar"));
    std::fs::remove_file(&target).expect("remove");
    std::fs::write(
        &target,
        archive(&[("../escape", tar::EntryType::Regular, b"abc")]),
    )
    .expect("tamper");
    let mut output = Vec::new();
    assert!(
        store
            .export_tar(&id, &mut output, &FilesystemPolicy::default())
            .is_err()
    );
    assert!(output.is_empty());
}

#[cfg(unix)]
#[test]
fn refuses_world_writable_root_and_symlink_or_hardlinked_archives() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let root = openshell_kata::boundary::filesystem::private_transfer_directory().expect("root");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o777)).expect("mode");
    assert!(ImportStore::open(root.path()).is_err());
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).expect("mode");
    let store = ImportStore::open(root.path()).expect("store");
    let id = store
        .import_tar(
            Cursor::new(archive(&[("safe", tar::EntryType::Regular, b"abc")])),
            &FilesystemPolicy::default(),
        )
        .expect("import");
    let target = root.path().join(format!("{id}.tar"));
    std::fs::hard_link(&target, root.path().join("hardlink")).expect("link");
    assert!(store.open_archive(&id).is_err());
    std::fs::remove_file(&target).expect("remove");
    symlink("hardlink", &target).expect("symlink");
    assert!(store.open_archive(&id).is_err());
}

#[test]
fn rejects_appended_payload_and_oversized_or_ambiguous_paths() {
    use openshell_kata::boundary::filesystem::validate_archive;
    let policy = FilesystemPolicy::default();
    let mut input = archive(&[("safe", tar::EntryType::Regular, b"a")]);
    input.extend_from_slice(b"hidden payload");
    assert!(validate_archive(Cursor::new(input), &policy).is_err());
    for path in [
        "a/./b".to_owned(),
        format!("{}file", "a/".repeat(33)),
        "".to_owned(),
        "control\nname".to_owned(),
    ] {
        assert!(
            validate_archive(
                Cursor::new(archive(&[(&path, tar::EntryType::Regular, b"a")])),
                &policy
            )
            .is_err(),
            "accepted {path:?}"
        );
    }
    let mut truncated = archive(&[("a", tar::EntryType::Regular, b"x")]);
    truncated.truncate(1024);
    assert!(validate_archive(Cursor::new(truncated), &policy).is_err());
}

#[test]
fn canonical_id_round_trip_removal_and_zero_limits() {
    let root = openshell_kata::boundary::filesystem::private_transfer_directory().expect("root");
    let store = ImportStore::open(root.path()).expect("store");
    let id = store
        .import_tar(
            Cursor::new(archive(&[("a", tar::EntryType::Regular, b"x")])),
            &FilesystemPolicy::default(),
        )
        .expect("import");
    assert_eq!(id.to_string().parse::<ImportId>().expect("parse"), id);
    assert!(id.to_string().to_uppercase().parse::<ImportId>().is_err());
    store.remove(&id).expect("remove");
    assert!(store.open_archive(&id).is_err());
    assert!(
        FilesystemPolicy {
            transfer_max_bytes: 0,
            ..FilesystemPolicy::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        FilesystemPolicy {
            transfer_max_entries: u64::MAX,
            ..FilesystemPolicy::default()
        }
        .validate()
        .is_err()
    );
    assert!(
        serde_json::from_str::<FilesystemPolicy>(
            r#"{"host_mounts":"allow","transfer_max_bytes":1,"transfer_max_entries":1}"#
        )
        .is_err()
    );
}

#[test]
fn io_errors_cleanup_staging_and_preserve_existing_archive() {
    use std::io;
    struct FailingReader;
    impl Read for FailingReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("injected read failure"))
        }
    }
    struct FailingWriter;
    impl io::Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("injected write failure"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let root = openshell_kata::boundary::filesystem::private_transfer_directory().expect("root");
    let store = ImportStore::open(root.path()).expect("store");
    assert!(
        store
            .import_tar(FailingReader, &FilesystemPolicy::default())
            .is_err()
    );
    assert_eq!(std::fs::read_dir(root.path()).expect("entries").count(), 0);
    let id = store
        .import_tar(
            Cursor::new(archive(&[("file", tar::EntryType::Regular, b"content")])),
            &FilesystemPolicy::default(),
        )
        .expect("import");
    assert!(
        store
            .export_tar(&id, FailingWriter, &FilesystemPolicy::default())
            .is_err()
    );
    assert_eq!(std::fs::read_dir(root.path()).expect("entries").count(), 1);
    assert!(store.open_archive(&id).is_ok());
}

#[test]
fn directory_content_and_excess_padding_are_rejected() {
    use openshell_kata::boundary::filesystem::validate_archive;
    assert!(
        validate_archive(
            Cursor::new(archive(&[("folder", tar::EntryType::Directory, b"bad")])),
            &FilesystemPolicy::default()
        )
        .is_err()
    );
    let policy = FilesystemPolicy {
        transfer_max_bytes: 1,
        transfer_max_entries: 1,
        ..FilesystemPolicy::default()
    };
    let mut excessive = archive(&[("file", tar::EntryType::Regular, b"x")]);
    excessive.extend_from_slice(&[0; 512]);
    assert!(validate_archive(Cursor::new(excessive), &policy).is_err());
}
