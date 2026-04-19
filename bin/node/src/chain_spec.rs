use sc_service::ChainType;
use serde_json::json;
use s3_registry_runtime::{AccountId, AuraId, GrandpaId, Signature, WASM_BINARY};
use sp_core::{sr25519, Pair, Public};
use sp_runtime::traits::{IdentifyAccount, Verify};

pub type ChainSpec = sc_service::GenericChainSpec;

type AccountPublic = <Signature as Verify>::Signer;

fn get_from_seed<TPublic: Public>(seed: &str) -> <TPublic::Pair as Pair>::Public {
    TPublic::Pair::from_string(&format!("//{seed}"), None)
        .expect("static values are valid; qed")
        .public()
}

fn get_account_id_from_seed<TPublic: Public>(seed: &str) -> AccountId
where
    AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
    AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

fn authority_keys_from_seed(seed: &str) -> (AuraId, GrandpaId) {
    (
        get_from_seed::<AuraId>(seed),
        get_from_seed::<GrandpaId>(seed),
    )
}

fn dev_genesis_patch() -> serde_json::Value {
    let alice: AccountId = get_account_id_from_seed::<sr25519::Public>("Alice");
    let bob: AccountId = get_account_id_from_seed::<sr25519::Public>("Bob");
    let (aura, grandpa) = authority_keys_from_seed("Alice");

    json!({
        "balances": {
            "balances": [
                [alice.clone(), 1_000_000_000_000_000_000u128],
                [bob.clone(),   1_000_000_000_000_000_000u128]
            ]
        },
        "sudo": {
            "key": alice
        },
        "aura": {
            "authorities": [aura]
        },
        "grandpa": {
            "authorities": [[grandpa, 1]]
        }
    })
}

pub fn development_chain_spec() -> Result<ChainSpec, String> {
    Ok(
        ChainSpec::builder(
            WASM_BINARY.ok_or_else(|| "Development wasm not available".to_string())?,
            None,
        )
        .with_name("Development")
        .with_id("dev")
        .with_chain_type(ChainType::Development)
        .with_genesis_config_patch(dev_genesis_patch())
        .build(),
    )
}
