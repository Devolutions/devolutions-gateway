use ironrdp_connector::sspi;

use crate::api::kdc_proxy::send_krb_message;
use crate::target_addr::TargetAddr;

pub(super) struct NetworkClient;

impl NetworkClient {
    pub(super) fn new() -> Self {
        Self {}
    }

    pub(super) async fn send(&self, request: &sspi::generator::NetworkRequest) -> anyhow::Result<Vec<u8>> {
        let target_addr = TargetAddr::parse(request.url.as_str(), Some(88))?;

        send_krb_message(&target_addr, &request.data)
            .await
            .map_err(|err| anyhow::Error::msg("failed to send KDC message").context(err))
    }
}
