use openshell_kata::upload::transfer_archive;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn streams_large_upload_through_small_buffers_without_losing_credit() {
    let expected = vec![0xa7; 16 * 1024 * 1024 + 123];
    let payload = expected.clone();
    let (mut producer, input) = tokio::io::duplex(1024);
    let (output, mut extractor) = tokio::io::duplex(512);
    let (acks, mut received_acks) = tokio::io::duplex(8);
    let sending = tokio::spawn(async move {
        producer.write_all(&payload).await.expect("write source");
        producer.shutdown().await.expect("source EOF");
    });
    let extracting = tokio::spawn(async move {
        let mut bytes = Vec::new();
        extractor
            .read_to_end(&mut bytes)
            .await
            .expect("read extractor");
        bytes
    });
    let acknowledging = tokio::spawn(async move {
        let mut totals = Vec::new();
        while let Ok(total) = received_acks.read_u64().await {
            totals.push(total);
        }
        totals
    });
    let total = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        transfer_archive(input, output, acks),
    )
    .await
    .expect("bounded transfer")
    .expect("upload transfer");
    sending.await.expect("producer task");
    let actual = extracting.await.expect("extractor task");
    let totals = acknowledging.await.expect("ack task");
    assert_eq!(actual, expected);
    assert_eq!(total, actual.len() as u64);
    assert_eq!(totals.first(), Some(&0));
    assert!(totals.windows(2).all(|window| window[0] < window[1]));
    assert!(totals.iter().all(|n| *n <= total));
}

#[tokio::test]
async fn closed_extractor_fails_promptly_instead_of_waiting_for_upload_eof() {
    let (mut source, input) = tokio::io::duplex(16);
    let (output, extractor) = tokio::io::duplex(16);
    let (acks, mut received_acks) = tokio::io::duplex(16);
    drop(extractor);
    source
        .write_all(b"partial archive")
        .await
        .expect("source bytes");
    let acknowledging = tokio::spawn(async move {
        let _ = received_acks.read_u64().await;
    });
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        transfer_archive(input, output, acks),
    )
    .await
    .expect("failure must not wait for source EOF");
    assert!(result.is_err());
    acknowledging.await.expect("ack task");
}
