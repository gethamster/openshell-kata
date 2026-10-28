use crate::{
    supervisor::{Output, Runtime},
    upload,
};
use anyhow::{Context, Result, bail};
use russh::{
    Channel, ChannelId,
    server::{self, Msg, Session},
};
use std::{collections::HashMap, os::unix::fs::PermissionsExt, sync::Arc};
use tokio::{
    io::AsyncWriteExt,
    net::UnixListener,
    process::Child,
    task::{JoinHandle, JoinSet},
};

pub async fn listen(
    runtime: Arc<Runtime>,
    host_key: &str,
) -> Result<(tempfile::TempDir, JoinHandle<()>)> {
    let directory = tempfile::Builder::new()
        .prefix("osk-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")?;
    let path = directory.path().join("ssh.sock");
    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let key =
        russh::keys::decode_secret_key(host_key, None).context("invalid gateway SSH host key")?;
    let config = Arc::new(server::Config {
        keys: vec![key],
        inactivity_timeout: None,
        ..Default::default()
    });
    let task = tokio::spawn(async move {
        let mut sessions = JoinSet::new();
        let connection_slots = Arc::new(tokio::sync::Semaphore::new(16));
        loop {
            tokio::select! {
                () = runtime.cancel.cancelled() => break,
                accepted = listener.accept() => match accepted {
                    Ok((stream, _)) => {
                        let Ok(permit)=connection_slots.clone().try_acquire_owned() else {continue;};
                        let handler = Handler { runtime: runtime.clone(), channels: HashMap::new() };
                        let config = config.clone();
                        sessions.spawn(async move { let _permit=permit; if let Ok(session) = server::run_stream(config, stream, handler).await { let _ = session.await; } });
                    }
                    Err(error) => { tracing::warn!(%error,"private SSH accept failed"); break; }
                },
                Some(_) = sessions.join_next(), if !sessions.is_empty() => {}
            }
        }
        sessions.abort_all();
        while sessions.join_next().await.is_some() {}
    });
    Ok((directory, task))
}

struct Handler {
    runtime: Arc<Runtime>,
    channels: HashMap<ChannelId, Channel<Msg>>,
}
impl Handler {
    fn dispatch(
        &mut self,
        id: ChannelId,
        operation: Operation,
        session: &mut Session,
    ) -> Result<()> {
        if self.runtime.vm_policy.is_some()
            && *self.runtime.phase.borrow() != crate::supervisor::Phase::Ready
        {
            session.channel_failure(id)?;
            return Ok(());
        }
        let Ok(permit) = self.runtime.operation_slots.clone().try_acquire_owned() else {
            session.channel_failure(id)?;
            return Ok(());
        };
        let Some(channel) = self.channels.remove(&id) else {
            bail!("SSH channel was not opened");
        };
        session.channel_success(id)?;
        let handle = session.handle();
        let runtime = self.runtime.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let result = match operation {
                Operation::Exec(command) if crate::download::is_archive_command(&command) => {
                    crate::download::serve(channel, runtime, &command).await
                }
                Operation::Exec(command) => match runtime.guest.exec(&runtime.config, &command) {
                    Ok(child) => bridge(channel, child, runtime).await,
                    Err(error) => Err(error),
                },
                Operation::Sftp if runtime.vm_policy.is_some() => Err(anyhow::anyhow!(
                    "SFTP is unsupported by the enforced transfer profile; use OpenShell upload/download"
                )),
                Operation::Sftp => match runtime.guest.sftp(&runtime.config) {
                    Ok(child) => bridge(channel, child, runtime).await,
                    Err(error) => Err(error),
                },
                Operation::Upload => upload::serve(channel, runtime).await,
                Operation::Main => attach_main(channel, runtime).await,
            };
            if let Err(error) = result {
                tracing::warn!(%error, "SSH operation failed");
                let _ = handle
                    .extended_data(id, 1, b"isolated guest operation failed\n".to_vec())
                    .await;
                let _ = handle.exit_status_request(id, 1).await;
                let _ = handle.eof(id).await;
                let _ = handle.close(id).await;
            }
        });
        Ok(())
    }
}
enum Operation {
    Exec(String),
    Sftp,
    Upload,
    Main,
}
impl server::Handler for Handler {
    type Error = anyhow::Error;
    async fn auth_none(&mut self, _user: &str) -> Result<server::Auth> {
        // This endpoint is a private UDS behind the authenticated gateway relay.
        // System ssh uses the local login name for upload; guest identity is
        // selected exclusively by trusted lifecycle metadata, never this name.
        Ok(server::Auth::Accept)
    }
    async fn auth_publickey(
        &mut self,
        user: &str,
        _: &russh::keys::PublicKey,
    ) -> Result<server::Auth> {
        self.auth_none(user).await
    }
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<()> {
        if self.channels.len() >= 64 {
            reply
                .reject(russh::ChannelOpenFailure::ResourceShortage)
                .await;
        } else {
            self.channels.insert(channel.id(), channel);
            reply.accept().await;
        }
        Ok(())
    }
    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<()> {
        if data.len() > 64 * 1024 {
            session.channel_failure(channel)?;
            return Ok(());
        }
        self.dispatch(
            channel,
            Operation::Exec(std::str::from_utf8(data)?.to_owned()),
            session,
        )
    }
    async fn shell_request(&mut self, channel: ChannelId, session: &mut Session) -> Result<()> {
        self.dispatch(channel, Operation::Exec("sh -l".to_owned()), session)
    }
    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<()> {
        let operation = match name {
            "sftp" => Operation::Sftp,
            "openshell-upload-v1" => Operation::Upload,
            "openshell-main" => Operation::Main,
            _ => {
                session.channel_failure(channel)?;
                return Ok(());
            }
        };
        self.dispatch(channel, operation, session)
    }
    async fn channel_close(&mut self, channel: ChannelId, _: &mut Session) -> Result<()> {
        self.channels.remove(&channel);
        Ok(())
    }
}

async fn bridge(channel: Channel<Msg>, mut child: Child, runtime: Arc<Runtime>) -> Result<()> {
    let (mut read, write) = channel.split();
    let mut stdin = child.stdin.take().context("guest stdin unavailable")?;
    let mut stdout = child.stdout.take().context("guest stdout unavailable")?;
    let mut stderr = child.stderr.take().context("guest stderr unavailable")?;
    let input = async move {
        tokio::io::copy(&mut read.make_reader(), &mut stdin).await?;
        stdin.shutdown().await?;
        drop(stdin);
        Ok::<_, std::io::Error>(())
    };
    let mut normal = write.make_writer();
    let mut errors = write.make_writer_ext(Some(1));
    let output = async {
        tokio::try_join!(
            tokio::io::copy(&mut stdout, &mut normal),
            tokio::io::copy(&mut stderr, &mut errors)
        )?;
        Ok::<_, std::io::Error>(())
    };
    tokio::pin!(input);
    let completion = async { tokio::try_join!(output, child.wait()) };
    tokio::pin!(completion);
    let result = tokio::select! {
        () = runtime.cancel.cancelled() => return Ok(()),
        result = &mut completion => result?,
        result = &mut input => {
            result?;
            tokio::select! {
                ()=runtime.cancel.cancelled()=>return Ok(()),
                result=&mut completion=>result?,
            }
        }
    };
    write
        .exit_status(u32::try_from(result.1.code().unwrap_or(1)).unwrap_or(1))
        .await?;
    write.eof().await?;
    write.close().await?;
    Ok(())
}

async fn attach_main(channel: Channel<Msg>, runtime: Arc<Runtime>) -> Result<()> {
    let mut updates = runtime.output.subscribe();
    let history: Vec<_> = runtime.history.lock().await.iter().cloned().collect();
    for message in history {
        send_output(&channel, message).await?;
    }
    let exit_code = *runtime.main_exit.borrow();
    if let Some(code) = exit_code {
        channel.exit_status(code).await?;
        channel.eof().await?;
        channel.close().await?;
        return Ok(());
    }
    loop {
        tokio::select! {
            () = runtime.cancel.cancelled() => return Ok(()),
            message = updates.recv() => { let message = message?; let done = matches!(message, Output::Exit(_)); send_output(&channel, message).await?; if done { return Ok(()); } }
        }
    }
}
async fn send_output(channel: &Channel<Msg>, output: Output) -> Result<()> {
    match output {
        Output::Stdout(data) => channel.data(&data[..]).await?,
        Output::Stderr(data) => channel.extended_data(1, &data[..]).await?,
        Output::Exit(code) => {
            channel.exit_status(code).await?;
            channel.eof().await?;
            channel.close().await?;
        }
    }
    Ok(())
}
