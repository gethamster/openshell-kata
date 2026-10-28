//! Real Unix socket readiness checks used by the adapter startup probe.

use openshell_kata::operator::socket_ready;
use std::{os::unix::net::UnixListener, time::Duration};

#[tokio::test]
async fn connects_to_a_live_socket_and_rejects_refused_missing_and_relative_paths() {
    let temporary = tempfile::Builder::new()
        .prefix("kop-")
        .tempdir_in("/tmp")
        .expect("socket root");
    let socket = temporary.path().join("driver.sock");
    let listener = UnixListener::bind(&socket).expect("listener");
    socket_ready(&socket).await.expect("live socket");
    drop(listener);
    let start = std::time::Instant::now();
    assert!(socket_ready(&socket).await.is_err());
    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(
        socket_ready(&temporary.path().join("missing.sock"))
            .await
            .is_err()
    );
    assert!(
        socket_ready(std::path::Path::new("relative.sock"))
            .await
            .is_err()
    );
}
