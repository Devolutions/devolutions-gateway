//! Process-level tests for RDP credential injection, reconnect, and fail-closed routing.
//!
//! These tests start a real Gateway, provision credentials over `/jet/preflight` the way DVLS
//! does, then connect to the TCP listener with an RDP preconnection blob. A loopback peer stands
//! in for the destination RDP server and records the X.224 Connection Request the proxy forwards.
//! Injection is observed from Gateway logs and from the rewritten mstshash cookie. CredSSP is not
//! completed: the contract under test is checkout, reconnect, and fail-closed routing.

use testsuite::rdp_injection::gateway::GatewayProc;
use testsuite::rdp_injection::preflight::provision_credentials;
use testsuite::rdp_injection::rdp::{FakeRdpTarget, connect_rdp_client};
use testsuite::rdp_injection::tokens::{association_token, next_id};
use testsuite::rdp_injection::{
    CLIENT_COOKIE, FORWARD_LOG, INJECT_LOG, KERBEROS_TARGET_USER, PUBLISHED_KDC_LOG, REGISTERED_KDC_LOG, TARGET_USER,
};
use tokio::time::Duration;

#[tokio::test]
async fn first_rdp_connection_injects_ntlm() -> anyhow::Result<()> {
    let target = FakeRdpTarget::start().await?;
    let mut gateway = GatewayProc::start().await?;

    let jti = next_id();
    let jet_aid = next_id();
    let token = association_token(&jti, &jet_aid, target.port, 60)?;
    provision_credentials(gateway.config.http_port(), &token, TARGET_USER, 300, None).await?;

    let _client = connect_rdp_client(gateway.config.tcp_port(), &token).await?;
    let logs = gateway.logs.wait_contains(INJECT_LOG).await?;
    assert!(
        logs.contains("kerberos=false"),
        "expected NTLM injection; logs:\n{logs}"
    );
    assert!(
        !logs.contains(FORWARD_LOG),
        "injection must not fall back to ordinary forward; logs:\n{logs}"
    );

    let cookies = target.wait_cookies(1).await?;
    assert_eq!(
        cookies,
        vec![TARGET_USER],
        "decoded X.224 cookie must be the injected user"
    );

    let _ = gateway.process.start_kill();
    Ok(())
}

#[tokio::test]
async fn reconnect_same_jwt_still_injects() -> anyhow::Result<()> {
    let target = FakeRdpTarget::start().await?;
    let mut gateway = GatewayProc::start().await?;

    let jti = next_id();
    let jet_aid = next_id();
    let token = association_token(&jti, &jet_aid, target.port, 60)?;
    provision_credentials(gateway.config.http_port(), &token, TARGET_USER, 300, None).await?;

    let first = connect_rdp_client(gateway.config.tcp_port(), &token).await?;
    gateway.logs.wait_count(INJECT_LOG, 1).await?;
    target.wait_cookies(1).await?;
    drop(first);

    let _second = connect_rdp_client(gateway.config.tcp_port(), &token).await?;
    let logs = gateway.logs.wait_count(INJECT_LOG, 2).await?;
    assert_eq!(
        logs.matches(INJECT_LOG).count(),
        2,
        "reconnect must inject exactly twice; logs:\n{logs}"
    );
    assert!(
        !logs.contains(FORWARD_LOG),
        "reconnect must keep injecting, not ordinary-forward; logs:\n{logs}"
    );

    let cookies = target.wait_cookies(2).await?;
    assert_eq!(
        cookies,
        vec![TARGET_USER, TARGET_USER],
        "both decoded X.224 cookies must be the injected user"
    );

    let _ = gateway.process.start_kill();
    Ok(())
}

#[tokio::test]
async fn expired_staging_uses_ordinary_forward() -> anyhow::Result<()> {
    let target = FakeRdpTarget::start().await?;
    let mut gateway = GatewayProc::start().await?;

    let jti = next_id();
    let jet_aid = next_id();
    let token = association_token(&jti, &jet_aid, target.port, 60)?;
    provision_credentials(gateway.config.http_port(), &token, TARGET_USER, 1, None).await?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let _client = connect_rdp_client(gateway.config.tcp_port(), &token).await?;
    let logs = gateway.logs.wait_contains(FORWARD_LOG).await?;
    assert!(
        !logs.contains(INJECT_LOG),
        "evicted staging credentials must not inject; logs:\n{logs}"
    );

    let cookies = target.wait_cookies(1).await?;
    assert_eq!(
        cookies,
        vec![CLIENT_COOKIE],
        "ordinary forward must keep the decoded client cookie"
    );

    let _ = gateway.process.start_kill();
    Ok(())
}

#[tokio::test]
async fn unprovisioned_rdp_uses_ordinary_forward() -> anyhow::Result<()> {
    let target = FakeRdpTarget::start().await?;
    let mut gateway = GatewayProc::start().await?;

    let jti = next_id();
    let jet_aid = next_id();
    let token = association_token(&jti, &jet_aid, target.port, 60)?;

    let _client = connect_rdp_client(gateway.config.tcp_port(), &token).await?;
    let logs = gateway.logs.wait_contains(FORWARD_LOG).await?;
    assert!(
        !logs.contains(INJECT_LOG),
        "absent mapping should ordinary-forward; logs:\n{logs}"
    );

    let cookies = target.wait_cookies(1).await?;
    assert_eq!(
        cookies,
        vec![CLIENT_COOKIE],
        "ordinary forward must keep the decoded client cookie"
    );

    let _ = gateway.process.start_kill();
    Ok(())
}

#[tokio::test]
async fn kerberos_reconnect_reuses_generation_until_reprovision() -> anyhow::Result<()> {
    let target = FakeRdpTarget::start().await?;
    let mut gateway = GatewayProc::start().await?;

    let jti = next_id();
    let jet_aid = next_id();
    let token = association_token(&jti, &jet_aid, target.port, 60)?;
    provision_credentials(
        gateway.config.http_port(),
        &token,
        KERBEROS_TARGET_USER,
        300,
        Some("tcp://127.0.0.1:88"),
    )
    .await?;

    // Keep overlapping reconnect sockets so the same-generation KDC lease stays live.
    let _first = connect_rdp_client(gateway.config.tcp_port(), &token).await?;
    let logs = gateway.logs.wait_count(INJECT_LOG, 1).await?;
    assert!(
        logs.contains("kerberos=true"),
        "expected Kerberos injection; logs:\n{logs}"
    );
    gateway.logs.wait_count(PUBLISHED_KDC_LOG, 1).await?;

    let _second = connect_rdp_client(gateway.config.tcp_port(), &token).await?;
    let logs = gateway.logs.wait_count(INJECT_LOG, 2).await?;
    assert_eq!(
        logs.matches("kerberos=true").count(),
        2,
        "same generation reconnect should still inject Kerberos; logs:\n{logs}"
    );
    gateway.logs.wait_count(REGISTERED_KDC_LOG, 2).await?;
    assert_eq!(
        logs.matches(PUBLISHED_KDC_LOG).count(),
        1,
        "same provisioning generation must reuse the interned synthetic KDC; logs:\n{logs}"
    );

    provision_credentials(
        gateway.config.http_port(),
        &token,
        KERBEROS_TARGET_USER,
        300,
        Some("tcp://127.0.0.1:88"),
    )
    .await?;

    let _third = connect_rdp_client(gateway.config.tcp_port(), &token).await?;
    let logs = gateway.logs.wait_count(INJECT_LOG, 3).await?;
    assert_eq!(
        logs.matches("kerberos=true").count(),
        3,
        "newer provisioning generation should replace and still inject; logs:\n{logs}"
    );
    let logs = gateway.logs.wait_count(PUBLISHED_KDC_LOG, 2).await?;
    assert_eq!(
        logs.matches(PUBLISHED_KDC_LOG).count(),
        2,
        "re-provision must publish exactly one extra synthetic KDC; logs:\n{logs}"
    );
    assert_eq!(
        logs.matches(REGISTERED_KDC_LOG).count(),
        3,
        "each connection should register a synthetic KDC lease; logs:\n{logs}"
    );
    assert!(
        !logs.contains(FORWARD_LOG),
        "Kerberos injection must not ordinary-forward; logs:\n{logs}"
    );

    let cookies = target.wait_cookies(3).await?;
    assert_eq!(
        cookies,
        vec![
            KERBEROS_TARGET_USER.to_owned(),
            KERBEROS_TARGET_USER.to_owned(),
            KERBEROS_TARGET_USER.to_owned()
        ],
        "each decoded X.224 cookie must be the Kerberos target user"
    );

    let _ = gateway.process.start_kill();
    Ok(())
}

#[tokio::test]
async fn domainless_target_stays_ntlm_even_with_krb_kdc() -> anyhow::Result<()> {
    let target = FakeRdpTarget::start().await?;
    let mut gateway = GatewayProc::start().await?;

    let jti = next_id();
    let jet_aid = next_id();
    let token = association_token(&jti, &jet_aid, target.port, 60)?;
    provision_credentials(
        gateway.config.http_port(),
        &token,
        TARGET_USER,
        300,
        Some("tcp://127.0.0.1:88"),
    )
    .await?;

    let _client = connect_rdp_client(gateway.config.tcp_port(), &token).await?;
    let logs = gateway.logs.wait_contains(INJECT_LOG).await?;
    assert!(
        logs.contains("kerberos=false"),
        "username without a realm must stay NTLM even if krb_kdc is provisioned; logs:\n{logs}"
    );

    let _ = gateway.process.start_kill();
    Ok(())
}

#[tokio::test]
async fn kerberos_injection_does_not_need_debug_flags() -> anyhow::Result<()> {
    let target = FakeRdpTarget::start().await?;
    let mut gateway = GatewayProc::start().await?;

    let jti = next_id();
    let jet_aid = next_id();
    let token = association_token(&jti, &jet_aid, target.port, 60)?;
    provision_credentials(
        gateway.config.http_port(),
        &token,
        KERBEROS_TARGET_USER,
        300,
        Some("tcp://127.0.0.1:88"),
    )
    .await?;

    let _client = connect_rdp_client(gateway.config.tcp_port(), &token).await?;
    let logs = gateway.logs.wait_contains(INJECT_LOG).await?;
    assert!(
        logs.contains("kerberos=true"),
        "Kerberos injection must run without debug flags; logs:\n{logs}"
    );

    let _ = gateway.process.start_kill();
    Ok(())
}
