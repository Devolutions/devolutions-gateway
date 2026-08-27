//! Kerberos credential injection against a mock KDC and IronRDP CredSSP server.
//!
//! Proves the target-leg path: Gateway fetches tickets from a TCP KDC (`kdc` crate from
//! sspi-rs) and completes CredSSP with a fake RDP acceptor. The Gateway-facing client uses
//! NTLM so the test does not depend on the in-process synthetic KDC.
//!
//! RDCleanPath coverage drives the public `ironrdp-agent` 0.1.0 CLI (`cargo install
//! ironrdp-agent --version 0.1.0`) over `ws://127.0.0.1/jet/rdp`.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use testsuite::rdp_injection::agent::{
    agent_query_logs, connect_ironrdp_rdcleanpath, ironrdp_agent_endpoint, require_ironrdp_agent, start_ironrdp_daemon,
};
use testsuite::rdp_injection::credssp::{
    complete_client_credssp, complete_ntlm_credssp, complete_raw_ntlm_credssp, connect_ntlm_client,
};
use testsuite::rdp_injection::gateway::GatewayProc;
use testsuite::rdp_injection::mock_kdc::{
    MockKdc, ObservedKdcReply, ObservedKdcReq, RefusingKdc, assert_target_kdc_as_and_tgs,
};
use testsuite::rdp_injection::mock_rdp::MockRdp;
use testsuite::rdp_injection::preflight::{provision_credentials, provision_mapping};
use testsuite::rdp_injection::rdp::{FakeClosedTarget, encode_hybrid_cr, encode_pcb};
use testsuite::rdp_injection::tls::install_crypto_provider;
use testsuite::rdp_injection::tokens::{association_token_for_host, kdc_proxy_url, next_id};
use testsuite::rdp_injection::{
    FORWARD_LOG, INJECT_LOG, KERBEROS_TARGET_USER, MISSING_LOG, PROXY_KERBEROS_USER, PROXY_USER,
    RDCLEANPATH_FORWARD_LOG, RDCLEANPATH_INJECT_LOG, REALM, SERVICE_HOST, TARGET_PASSWORD, TARGET_USER,
};
use tokio::io::AsyncWriteExt as _;
use tokio::net::TcpStream;

#[tokio::test]
async fn kerberos_injection_completes_credssp_against_mock_kdc() -> anyhow::Result<()> {
    install_crypto_provider();
    let kdc = MockKdc::start().await?;
    let rdp = MockRdp::start_kerberos(kdc.url()).await?;
    let mut gateway = GatewayProc::start().await?;

    let jti = next_id();
    let jet_aid = next_id();
    let token = association_token_for_host(&jti, &jet_aid, rdp.port, 60)?;
    provision_credentials(
        gateway.config.http_port(),
        &token,
        KERBEROS_TARGET_USER,
        300,
        Some(&kdc.url()),
    )
    .await?;

    let tls = connect_ntlm_client(gateway.config.tcp_port(), &token).await?;
    complete_ntlm_credssp(tls)
        .await
        .context("Gateway-facing NTLM CredSSP")?;
    rdp.wait_credssp()
        .await
        .with_context(|| format!("gateway logs:\n{}", gateway.logs.snapshot()))?;
    anyhow::ensure!(
        kdc.exchanges() >= 2,
        "expected AS-REQ and TGS-REQ against the mock KDC; exchanges={}; gateway logs:\n{}",
        kdc.exchanges(),
        gateway.logs.snapshot()
    );
    assert_target_kdc_as_and_tgs(&kdc)?;
    anyhow::ensure!(
        rdp.finished_account().as_deref() == Some("administrator"),
        "RDP CredSSP Finished account must be administrator; got={:?}; cookies={:?}",
        rdp.finished_account(),
        rdp.cookies()
    );
    anyhow::ensure!(
        rdp.cookies().iter().any(|cookie| cookie == KERBEROS_TARGET_USER),
        "RDP X.224 cookie must be {KERBEROS_TARGET_USER}; cookies={:?}",
        rdp.cookies()
    );

    let _ = gateway.process.start_kill();
    Ok(())
}

#[tokio::test]
async fn kerberos_client_and_target_legs_complete_credssp() -> anyhow::Result<()> {
    install_crypto_provider();
    let kdc = MockKdc::start().await?;
    let rdp = MockRdp::start_kerberos(kdc.url()).await?;
    let mut gateway = GatewayProc::start().await?;

    let jti = next_id();
    let jet_aid = next_id();
    let token = association_token_for_host(&jti, &jet_aid, rdp.port, 60)?;
    provision_mapping(
        gateway.config.http_port(),
        &token,
        PROXY_KERBEROS_USER,
        KERBEROS_TARGET_USER,
        TARGET_PASSWORD,
        300,
        Some(&kdc.url()),
    )
    .await?;

    let kdc_proxy = kdc_proxy_url(gateway.config.http_port(), &jti)?;
    let proxy_replies = Mutex::new(Vec::new());
    let proxy_requests = Mutex::new(Vec::new());
    let tls = connect_ntlm_client(gateway.config.tcp_port(), &token).await?;
    complete_client_credssp(
        tls,
        PROXY_KERBEROS_USER,
        Some(&kdc_proxy),
        false,
        Some(&proxy_replies),
        Some(&proxy_requests),
    )
    .await
    .with_context(|| {
        format!(
            "client-leg Kerberos CredSSP; gateway logs:\n{}",
            gateway.logs.snapshot()
        )
    })?;
    rdp.wait_credssp().await.with_context(|| {
        format!(
            "target-leg Kerberos CredSSP; gateway logs:\n{}",
            gateway.logs.snapshot()
        )
    })?;
    anyhow::ensure!(
        kdc.exchanges() >= 2,
        "target-leg must talk to the mock KDC; exchanges={}; logs:\n{}",
        kdc.exchanges(),
        gateway.logs.snapshot()
    );
    assert_target_kdc_as_and_tgs(&kdc)?;
    let replies = proxy_replies.lock().expect("proxy reply mutex").clone();
    anyhow::ensure!(
        replies.contains(&ObservedKdcReply::AsRep) && replies.contains(&ObservedKdcReply::TgsRep),
        "/jet/KdcProxy must return AS-REP and TGS-REP (PREAUTH KRB-ERROR is allowed first); replies={replies:?}"
    );
    let requests = proxy_requests.lock().expect("proxy request mutex").clone();
    anyhow::ensure!(
        requests.iter().any(|req| matches!(
            req,
            ObservedKdcReq::As { cname, realm }
                if cname.eq_ignore_ascii_case("injected-proxy-user") && realm.eq_ignore_ascii_case(REALM)
        )),
        "synthetic KDC AS-REQ must be proxy user injected-proxy-user@{REALM}; requests={requests:?}"
    );
    anyhow::ensure!(
        requests.iter().any(|req| matches!(
            req,
            ObservedKdcReq::Tgs { sname, realm }
                if *sname == ["TERMSRV", SERVICE_HOST] && realm.eq_ignore_ascii_case(REALM)
        )),
        "synthetic KDC TGS-REQ must be TERMSRV/{SERVICE_HOST}; requests={requests:?}"
    );
    anyhow::ensure!(
        rdp.finished_account().as_deref() == Some("administrator"),
        "RDP CredSSP Finished account must be administrator; got={:?}",
        rdp.finished_account()
    );
    anyhow::ensure!(
        rdp.cookies().iter().any(|cookie| cookie == KERBEROS_TARGET_USER),
        "RDP X.224 cookie must be {KERBEROS_TARGET_USER}; cookies={:?}",
        rdp.cookies()
    );

    let _ = gateway.process.start_kill();
    Ok(())
}

#[tokio::test]
async fn kerberos_wrong_target_password_fails_closed() -> anyhow::Result<()> {
    install_crypto_provider();
    let kdc = MockKdc::start().await?;
    let rdp = MockRdp::start_kerberos(kdc.url()).await?;
    let mut gateway = GatewayProc::start().await?;

    let jti = next_id();
    let jet_aid = next_id();
    let token = association_token_for_host(&jti, &jet_aid, rdp.port, 60)?;
    provision_mapping(
        gateway.config.http_port(),
        &token,
        PROXY_USER,
        KERBEROS_TARGET_USER,
        "wrong-target-password",
        300,
        Some(&kdc.url()),
    )
    .await?;

    let tls = connect_ntlm_client(gateway.config.tcp_port(), &token).await?;
    let _ = complete_ntlm_credssp(tls).await;
    let logs = gateway.logs.wait_contains(INJECT_LOG).await?;
    anyhow::ensure!(
        logs.contains("kerberos=true"),
        "wrong password must still start Kerberos injection; logs:\n{logs}"
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if kdc.requests().iter().any(|req| {
            matches!(
                req,
                ObservedKdcReq::As { cname, realm }
                    if cname.eq_ignore_ascii_case("administrator") && realm.eq_ignore_ascii_case(REALM)
            )
        }) {
            break;
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "timed out waiting for AS-REQ as administrator; requests={:?}",
                kdc.requests()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    anyhow::ensure!(
        !rdp.credssp_ok() && rdp.finished_account().is_none(),
        "wrong target password must not complete Kerberos CredSSP; account={:?}; logs:\n{}",
        rdp.finished_account(),
        gateway.logs.snapshot()
    );
    anyhow::ensure!(
        !kdc.requests()
            .iter()
            .any(|req| matches!(req, ObservedKdcReq::Tgs { .. })),
        "wrong password must not obtain a TGS; requests={:?}",
        kdc.requests()
    );
    anyhow::ensure!(
        rdp.cookies().iter().any(|cookie| cookie == KERBEROS_TARGET_USER),
        "wrong password still rewrites the X.224 cookie; cookies={:?}",
        rdp.cookies()
    );
    let logs = gateway.logs.snapshot();
    anyhow::ensure!(
        !logs.contains(FORWARD_LOG),
        "wrong password must not ordinary-forward; logs:\n{logs}"
    );

    let _ = gateway.process.start_kill();
    Ok(())
}

#[tokio::test]
async fn kerberos_kdc_down_fails_closed() -> anyhow::Result<()> {
    install_crypto_provider();
    let kdc = RefusingKdc::start().await?;
    let rdp_kdc = MockKdc::start().await?;
    let rdp = MockRdp::start_kerberos(rdp_kdc.url()).await?;
    let mut gateway = GatewayProc::start().await?;

    let jti = next_id();
    let jet_aid = next_id();
    let token = association_token_for_host(&jti, &jet_aid, rdp.port, 60)?;
    provision_credentials(
        gateway.config.http_port(),
        &token,
        KERBEROS_TARGET_USER,
        300,
        Some(&kdc.url()),
    )
    .await?;

    let tls = connect_ntlm_client(gateway.config.tcp_port(), &token).await?;
    let _ = complete_ntlm_credssp(tls).await;
    let logs = gateway.logs.wait_contains(INJECT_LOG).await?;
    anyhow::ensure!(
        logs.contains("kerberos=true"),
        "KDC down must still start Kerberos injection; logs:\n{logs}"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while kdc.accepted() == 0 {
        if Instant::now() >= deadline {
            anyhow::bail!("Gateway never TCP-connected the provisioned KDC");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    anyhow::ensure!(
        !rdp.credssp_ok() && rdp.finished_account().is_none(),
        "unreachable KDC must not complete CredSSP; account={:?}; logs:\n{}",
        rdp.finished_account(),
        gateway.logs.snapshot()
    );
    anyhow::ensure!(
        rdp.cookies().iter().any(|cookie| cookie == KERBEROS_TARGET_USER),
        "KDC down still rewrites the X.224 cookie; cookies={:?}",
        rdp.cookies()
    );
    anyhow::ensure!(
        kdc.accepted() >= 1,
        "Gateway must TCP-connect the provisioned KDC; accepted={}",
        kdc.accepted()
    );
    let logs = gateway.logs.snapshot();
    anyhow::ensure!(
        !logs.contains(FORWARD_LOG),
        "KDC down must not ordinary-forward; logs:\n{logs}"
    );

    let _ = gateway.process.start_kill();
    Ok(())
}

#[tokio::test]
async fn kerberos_missing_krb_kdc_fails_closed() -> anyhow::Result<()> {
    let rdp = FakeClosedTarget::start().await?;
    let mut gateway = GatewayProc::start().await?;

    let jti = next_id();
    let jet_aid = next_id();
    let token = association_token_for_host(&jti, &jet_aid, rdp.port, 60)?;
    provision_credentials(gateway.config.http_port(), &token, KERBEROS_TARGET_USER, 300, None).await?;

    let mut stream = TcpStream::connect(("127.0.0.1", gateway.config.tcp_port()))
        .await
        .context("connect gateway TCP")?;
    stream.write_all(&encode_pcb(&token)?).await.context("write PCB")?;
    stream.write_all(&encode_hybrid_cr()?).await.context("write CR")?;
    stream.flush().await.context("flush CR")?;
    let logs = gateway.logs.wait_contains(MISSING_LOG).await?;
    anyhow::ensure!(
        !logs.contains(FORWARD_LOG) && !logs.contains(INJECT_LOG),
        "missing krb_kdc must fail closed; logs:\n{logs}"
    );
    tokio::time::sleep(Duration::from_millis(250)).await;
    anyhow::ensure!(
        rdp.accepted() == 0,
        "missing krb_kdc must not dial the target; accepted={}",
        rdp.accepted()
    );
    let _ = gateway.process.start_kill();
    Ok(())
}

#[tokio::test]
async fn ntlm_injection_completes_credssp_both_legs() -> anyhow::Result<()> {
    install_crypto_provider();
    let rdp = MockRdp::start_ntlm().await?;
    let mut gateway = GatewayProc::start().await?;

    let jti = next_id();
    let jet_aid = next_id();
    let token = association_token_for_host(&jti, &jet_aid, rdp.port, 60)?;
    provision_credentials(gateway.config.http_port(), &token, TARGET_USER, 300, None).await?;

    let tls = connect_ntlm_client(gateway.config.tcp_port(), &token).await?;
    complete_raw_ntlm_credssp(tls)
        .await
        .with_context(|| format!("client-leg NTLM CredSSP; logs:\n{}", gateway.logs.snapshot()))?;
    rdp.wait_credssp()
        .await
        .with_context(|| format!("target-leg NTLM CredSSP; logs:\n{}", gateway.logs.snapshot()))?;
    let logs = gateway.logs.wait_contains(INJECT_LOG).await?;
    anyhow::ensure!(
        logs.contains("kerberos=false"),
        "expected NTLM injection; logs:\n{logs}"
    );
    anyhow::ensure!(
        rdp.finished_account().as_deref() == Some(TARGET_USER),
        "RDP NTLM CredSSP Finished account must be {TARGET_USER}; got={:?}",
        rdp.finished_account()
    );
    anyhow::ensure!(
        rdp.cookies().iter().any(|cookie| cookie == TARGET_USER),
        "RDP X.224 cookie must be {TARGET_USER}; cookies={:?}",
        rdp.cookies()
    );

    let _ = gateway.process.start_kill();
    Ok(())
}

#[tokio::test]
async fn ironrdp_agent_rdcleanpath_ntlm_injection() -> anyhow::Result<()> {
    let Some(bin) = require_ironrdp_agent()? else {
        return Ok(());
    };
    install_crypto_provider();
    let rdp = MockRdp::start_ntlm().await?;
    let mut gateway = GatewayProc::start().await?;
    let endpoint = ironrdp_agent_endpoint();
    let mut daemon = start_ironrdp_daemon(&bin, &endpoint).await?;

    let jti = next_id();
    let jet_aid = next_id();
    let token = association_token_for_host(&jti, &jet_aid, rdp.port, 60)?;
    provision_credentials(gateway.config.http_port(), &token, TARGET_USER, 300, None).await?;

    let mut connect = connect_ironrdp_rdcleanpath(
        &bin,
        &endpoint,
        &format!("{SERVICE_HOST}:{}", rdp.port),
        &token,
        gateway.config.http_port(),
    )
    .await?;
    let wait = rdp.wait_credssp().await;
    let agent_logs = agent_query_logs(&bin, &endpoint).await;
    wait.with_context(|| {
        format!(
            "RDCleanPath NTLM target CredSSP; gateway logs:\n{}\nagent logs:\n{agent_logs}",
            gateway.logs.snapshot()
        )
    })?;
    let logs = gateway.logs.snapshot();
    anyhow::ensure!(
        logs.contains(RDCLEANPATH_INJECT_LOG),
        "RDCleanPath must take the injection path; logs:\n{logs}"
    );
    anyhow::ensure!(
        !logs.contains(RDCLEANPATH_FORWARD_LOG),
        "RDCleanPath injection must not ordinary-forward; logs:\n{logs}"
    );
    anyhow::ensure!(
        rdp.finished_account().as_deref() == Some(TARGET_USER),
        "RDP NTLM CredSSP Finished account must be {TARGET_USER}; got={:?}",
        rdp.finished_account()
    );
    anyhow::ensure!(
        rdp.cookies().iter().any(|cookie| cookie == PROXY_USER),
        "RDCleanPath forwards the client X.224 cookie; cookies={:?}",
        rdp.cookies()
    );

    let _ = connect.start_kill();
    let _ = daemon.start_kill();
    let _ = gateway.process.start_kill();
    Ok(())
}

#[tokio::test]
async fn ironrdp_agent_rdcleanpath_kerberos_injection() -> anyhow::Result<()> {
    let Some(bin) = require_ironrdp_agent()? else {
        return Ok(());
    };
    install_crypto_provider();
    let kdc = MockKdc::start().await?;
    let rdp = MockRdp::start_kerberos(kdc.url()).await?;
    let mut gateway = GatewayProc::start().await?;
    let endpoint = ironrdp_agent_endpoint();
    let mut daemon = start_ironrdp_daemon(&bin, &endpoint).await?;

    let jti = next_id();
    let jet_aid = next_id();
    let token = association_token_for_host(&jti, &jet_aid, rdp.port, 60)?;
    provision_credentials(
        gateway.config.http_port(),
        &token,
        KERBEROS_TARGET_USER,
        300,
        Some(&kdc.url()),
    )
    .await?;

    let mut connect = connect_ironrdp_rdcleanpath(
        &bin,
        &endpoint,
        &format!("{SERVICE_HOST}:{}", rdp.port),
        &token,
        gateway.config.http_port(),
    )
    .await?;
    let wait = rdp.wait_credssp().await;
    let agent_logs = agent_query_logs(&bin, &endpoint).await;
    wait.with_context(|| {
        format!(
            "RDCleanPath Kerberos target CredSSP; gateway logs:\n{}\nagent logs:\n{agent_logs}",
            gateway.logs.snapshot()
        )
    })?;
    assert_target_kdc_as_and_tgs(&kdc)?;
    let logs = gateway.logs.snapshot();
    anyhow::ensure!(
        logs.contains(RDCLEANPATH_INJECT_LOG),
        "RDCleanPath must take the injection path; logs:\n{logs}"
    );
    anyhow::ensure!(
        !logs.contains(RDCLEANPATH_FORWARD_LOG),
        "RDCleanPath injection must not ordinary-forward; logs:\n{logs}"
    );
    anyhow::ensure!(
        rdp.finished_account().as_deref() == Some("administrator"),
        "RDP CredSSP Finished account must be administrator; got={:?}",
        rdp.finished_account()
    );
    anyhow::ensure!(
        rdp.cookies().iter().any(|cookie| cookie == PROXY_USER),
        "RDCleanPath forwards the client X.224 cookie; cookies={:?}",
        rdp.cookies()
    );

    let _ = connect.start_kill();
    let _ = daemon.start_kill();
    let _ = gateway.process.start_kill();
    Ok(())
}
