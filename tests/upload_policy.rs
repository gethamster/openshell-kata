use openshell_kata::{boundary::filesystem::FilesystemPolicy, upload::receive_validated_archive};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn tar_bytes(path: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut builder = tar::Builder::new(&mut bytes);
    let mut header = tar::Header::new_ustar();
    header.as_mut_bytes()[..path.len()].copy_from_slice(path.as_bytes());
    header.set_size(body.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, body).expect("fixture");
    builder.finish().expect("finish");
    drop(builder);
    bytes
}

#[tokio::test]
async fn validates_before_extraction_and_preserves_large_upload_acks() {
    let content = vec![b'x'; 16 * 1024 * 1024];
    let raw = tar_bytes("./project/data.bin", &content);
    let wire_len = raw.len() as u64;
    let (mut sender, input) = tokio::io::duplex(32 * 1024);
    let (acks, mut ack_reader) = tokio::io::duplex(1024);
    let send = async move {
        sender.write_all(&raw).await.expect("send");
        sender.shutdown().await.expect("eof");
    };
    let collect = async move {
        let mut received = Vec::new();
        while let Ok(ack) = ack_reader.read_u64().await {
            received.push(ack);
        }
        received
    };
    let policy = FilesystemPolicy::default();
    let (validated, (), received) = tokio::join!(
        receive_validated_archive(input, acks, &policy),
        send,
        collect
    );
    let upload = validated.expect("valid upload");
    assert_eq!(upload.received_bytes(), wire_len);
    assert_eq!(received.first(), Some(&0));
    assert!(received.windows(2).all(|values| values[1] > values[0]));
    assert!(received.len() >= 64);
    let (writer, mut reader) = tokio::io::duplex(4096);
    let (replay, result) = tokio::join!(upload.replay_to(writer), async {
        let mut data = Vec::new();
        reader.read_to_end(&mut data).await.expect("read");
        data
    });
    replay.expect("replay");
    let mut archive = tar::Archive::new(result.as_slice());
    let mut entry = archive
        .entries()
        .expect("entries")
        .next()
        .expect("entry")
        .expect("valid");
    assert_eq!(
        entry.path().expect("path").to_str(),
        Some("project/data.bin")
    );
    let mut decoded = Vec::new();
    std::io::Read::read_to_end(&mut entry, &mut decoded).expect("body");
    assert_eq!(decoded, content);
}

#[tokio::test]
async fn malformed_and_oversize_input_never_becomes_replayable() {
    for raw in [tar_bytes("../escape", b"bad"), vec![0xff; 2048]] {
        assert!(
            receive_validated_archive(
                raw.as_slice(),
                tokio::io::sink(),
                &FilesystemPolicy::default()
            )
            .await
            .is_err()
        );
    }
    let policy = FilesystemPolicy {
        transfer_max_bytes: 1,
        ..FilesystemPolicy::default()
    };
    assert!(
        receive_validated_archive(
            tar_bytes("big", b"too big").as_slice(),
            tokio::io::sink(),
            &policy
        )
        .await
        .is_err()
    );
}

#[tokio::test(start_paused = true)]
async fn idle_upload_fails_without_waiting_for_peer_eof() {
    let (_sender, input) = tokio::io::duplex(1024);
    let result =
        receive_validated_archive(input, tokio::io::sink(), &FilesystemPolicy::default()).await;
    assert!(result.is_err());
    assert!(
        result
            .err()
            .expect("error")
            .to_string()
            .contains("idle timeout")
    );
}
