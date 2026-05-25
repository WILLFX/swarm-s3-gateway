use anyhow::Result;
use trustless_proxy::{
    TrustlessProxyConfig, TrustlessRecipientKeyring, UnimplementedTrustlessRecipientKeyring,
};

fn main() -> Result<()> {
    let config = TrustlessProxyConfig::from_env()?;
    let keyring = UnimplementedTrustlessRecipientKeyring;

    println!(
        "trustless-local-proxy scaffold listen={}:{} remote_gateway={} chain_rpc={} local_account={} keystore={} keyring={}",
        config.listen_host,
        config.listen_port,
        config.remote_gateway_url,
        config.chain_rpc_url,
        config.local_account,
        config.keystore_path.display(),
        keyring.keyring_name()
    );

    Ok(())
}
