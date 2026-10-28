//! Serialize authenticated relay handshakes against credential lineage rotation.
use anyhow::Result;
use std::{future::Future, time::Duration};
use tokio::{
    sync::RwLock,
    time::{Instant, Interval},
};

const REFRESH_INTERVAL: Duration = Duration::from_secs(300);

pub(super) fn refresh_timer() -> Interval {
    tokio::time::interval_at(Instant::now() + REFRESH_INTERVAL, REFRESH_INTERVAL)
}

pub(super) async fn handshake<T>(
    gate: &RwLock<()>,
    operation: impl Future<Output = Result<T>>,
) -> Result<T> {
    let _guard = gate.read().await;
    operation.await
}

pub(super) async fn rotate<T>(
    gate: &RwLock<()>,
    operation: impl Future<Output = Result<T>>,
) -> Result<T> {
    let _guard = gate.write().await;
    operation.await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::sync::Notify;

    #[tokio::test(start_paused = true)]
    async fn periodic_renewal_waits_until_the_next_interval() {
        let mut interval = refresh_timer();
        assert!(
            tokio::time::timeout(Duration::from_millis(1), interval.tick())
                .await
                .is_err(),
            "periodic renewal must not duplicate the completed bootstrap renewal"
        );
        tokio::time::advance(REFRESH_INTERVAL).await;
        interval.tick().await;
    }

    #[tokio::test]
    async fn relay_waits_for_the_replacement_of_a_consumed_credential() -> Result<()> {
        let gate = Arc::new(RwLock::new(()));
        let versions = Arc::new((AtomicUsize::new(0), AtomicUsize::new(0)));
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let rotation = {
            let gate = gate.clone();
            let versions = versions.clone();
            let started = started.clone();
            let release = release.clone();
            tokio::spawn(async move {
                rotate(&gate, async {
                    versions.0.store(1, Ordering::SeqCst);
                    started.notify_one();
                    release.notified().await;
                    versions.1.store(1, Ordering::SeqCst);
                    Ok(())
                })
                .await
            })
        };
        started.notified().await;
        let mut relay = {
            let gate = gate.clone();
            let versions = versions.clone();
            tokio::spawn(async move {
                handshake(&gate, async {
                    anyhow::ensure!(
                        versions.0.load(Ordering::SeqCst) == versions.1.load(Ordering::SeqCst),
                        "relay attempted a consumed credential"
                    );
                    Ok(())
                })
                .await
            })
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut relay)
                .await
                .is_err(),
            "a pending refresh must finish before a new handshake"
        );
        release.notify_one();
        rotation.await??;
        relay.await??;
        Ok(())
    }

    #[tokio::test]
    async fn rotation_waits_for_an_existing_authenticated_handshake() -> Result<()> {
        let gate = Arc::new(RwLock::new(()));
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let relay = {
            let gate = gate.clone();
            let started = started.clone();
            let release = release.clone();
            tokio::spawn(async move {
                handshake(&gate, async {
                    started.notify_one();
                    release.notified().await;
                    Ok(())
                })
                .await
            })
        };
        started.notified().await;
        let mut rotation = {
            let gate = gate.clone();
            tokio::spawn(async move { rotate(&gate, async { Ok(()) }).await })
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut rotation)
                .await
                .is_err(),
            "rotation must not consume a bearer while its handshake is in flight"
        );
        release.notify_one();
        relay.await??;
        rotation.await??;
        Ok(())
    }
}
