use super::*;

async fn result(
    mut channel: russh::Channel<client::Msg>,
) -> anyhow::Result<(Vec<u8>, Option<u32>)> {
    channel.eof().await?;
    let mut output = Vec::new();
    let mut exit = None;
    while let Some(message) = tokio::time::timeout(Duration::from_secs(5), channel.wait()).await? {
        match message {
            ChannelMsg::Data { data } => output.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
            _ => {}
        }
    }
    Ok((output, exit))
}

#[tokio::test]
async fn ssh_banner_advertises_the_implemented_no_login_shell_contract() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    assert!(
        fixture
            .banner
            .lock()
            .expect("banner")
            .starts_with(b"SSH-2.0-OpenShell_Kata_")
    );
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn no_login_shell_skips_startup_files_and_keeps_literal_command_arguments()
-> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let startup_marker = fixture._files.path().join("startup-ran");
    let injected_marker = fixture._files.path().join("injected");
    std::fs::write(
        fixture._files.path().join("startup-profile"),
        format!(
            "touch {}\n",
            openshell_kata::config::shell_quote(&startup_marker.to_string_lossy())
        ),
    )?;
    let literal = format!(
        "spaces 'quotes' ; $(touch {})\n$HOME",
        injected_marker.display()
    );
    let command = format!(
        "printf '%s' {}",
        openshell_kata::config::shell_quote(&literal)
    );
    let channel = fixture.client.channel_open_session().await?;
    channel
        .set_env(false, "OPENSHELL_NO_LOGIN_SHELL", "1")
        .await?;
    channel.exec(true, command).await?;
    let (output, exit) = result(channel).await?;
    assert_eq!(
        output,
        literal.as_bytes(),
        "SSH execution must preserve the gateway's quoted command exactly"
    );
    assert_eq!(exit, Some(0));
    assert!(
        !startup_marker.exists(),
        "non-login execution must not source the startup fixture"
    );
    assert!(
        !injected_marker.exists(),
        "literal arguments must not become shell syntax"
    );
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn shell_opt_out_is_channel_local_and_arbitrary_environment_is_rejected() -> anyhow::Result<()>
{
    let fixture = Fixture::new().await?;
    let opted_out = fixture.client.channel_open_session().await?;
    opted_out
        .set_env(false, "OPENSHELL_NO_LOGIN_SHELL", "1")
        .await?;
    let normal = fixture.client.channel_open_session().await?;
    normal.exec(true, "fixture-output").await?;
    let (output, exit) = result(normal).await?;
    assert_eq!((output, exit), (b"normal".to_vec(), Some(7)));
    opted_out.exec(true, "printf no-login").await?;
    assert_eq!(result(opted_out).await?, (b"no-login".to_vec(), Some(0)));
    let commands = std::fs::read_to_string(fixture._files.path().join("shell-commands"))?;
    assert!(
        commands.contains("exec /bin/bash -l -c 'fixture-output'"),
        "another channel must keep default login-shell behavior"
    );
    let mut rejected = fixture.client.channel_open_session().await?;
    rejected.set_env(true, "BASH_ENV", "untrusted").await?;
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), rejected.wait()).await?,
        Some(ChannelMsg::Failure)
    ));
    rejected.close().await?;
    fixture.close().await;
    Ok(())
}

#[tokio::test]
async fn explicit_stdin_eof_drains_both_outputs_and_preserves_nonzero_exit() -> anyhow::Result<()> {
    let fixture = Fixture::new().await?;
    let mut channel = fixture.client.channel_open_session().await?;
    channel
        .set_env(false, "OPENSHELL_NO_LOGIN_SHELL", "1")
        .await?;
    channel
        .exec(true, "cat; printf diagnostic >&2; exit 7")
        .await?;
    let input = b"interactive input\0with binary bytes\n";
    channel.data(&input[..]).await?;
    channel.eof().await?;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit = None;
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(message) = channel.wait().await {
            match message {
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, .. } => stderr.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                _ => {}
            }
        }
    })
    .await?;
    assert_eq!(
        stdout, input,
        "EOF must reach cat without losing preceding binary stdin"
    );
    assert_eq!(
        stderr, b"diagnostic",
        "stdin EOF must leave stderr available for draining"
    );
    assert_eq!(exit, Some(7), "terminal status must follow output draining");
    fixture.close().await;
    Ok(())
}
