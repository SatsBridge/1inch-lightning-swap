use anyhow::{bail, Context, Result};
use std::str::FromStr;

use ed25519_dalek::{Keypair, PublicKey, SecretKey, SIGNATURE_LENGTH};
use everscale_rpc_client::RpcClient;

use nekoton::core::models::{Expiration};

//use nekoton::core::token_wallet::{RootTokenContractState, TokenWalletContractState};
use nekoton::core::ton_wallet::{compute_address, Gift, TransferAction, WalletType};
use nekoton::crypto::{derive_from_phrase, UnsignedMessage};
use nekoton::transport::models::ExistingContract;
use nekoton_abi::num_bigint::BigUint;

use nekoton_abi::{BigUint128, MessageBuilder};
use nekoton_contracts::tip3_1;

use nekoton_utils::{SimpleClock, TrustMe};


use ton_block::{MsgAddressInt};
use ton_types::{SliceData};
use url::Url;

/*
use crate::htlc::htlc_forwarder_contract;
pub mod abi;
pub mod build_payload;
pub mod hash;
pub mod htlc;
pub mod models;
*/

pub const DEFAULT_ABI_VERSION: ton_abi::contract::AbiVersion = ton_abi::contract::ABI_VERSION_2_0;
pub const DEFAULT_EXPIRATION_TIMEOUT: u32 = 120; // sec
pub const INITIAL_BALANCE: u64 = 100_000_000; // 0.1 EVER
pub const ATTACHED_AMOUNT: u64 = 200_000_000; // 0.1 EVER

// Wallet struct for managing transactions
pub struct Wallet {
    pub address: MsgAddressInt,
    pub state: ExistingContract,
    pub keypair: Keypair,
    pub client: RpcClient,
}

impl Wallet {
    // Creates a new wallet instance
    pub async fn new_from_keystore(keystore: &str, wallet: &str, rpc_url: &str) -> Result<Self> {
        #[derive(serde::Deserialize)]
        struct Content {
            mnemonic: Option<String>,
            secret: Option<[u8; 32]>,
        }
        let data = std::fs::read_to_string(keystore).context("Failed to load keys")?;
        let Content { secret, mnemonic } = serde_json::from_str(&data).context("Invalid keys")?;

        let keypair = match (mnemonic, secret) {
            (None, None) => {
                bail!("Neither mnemonic nor secret were provided")
            }
            (Some(_), Some(_)) => {
                bail!("Both mnemonic and secret were provided")
            }
            (None, Some(s)) => {
                let sk = SecretKey::from_bytes(s.as_ref())?;
                let pk = PublicKey::from(&sk);
                Keypair {
                    secret: sk,
                    public: pk,
                }
            }
            (Some(seed), None) => {
                derive_from_phrase(&seed, nekoton::crypto::MnemonicType::Labs(0))?
            }
        };

        let wtype = WalletType::from_str(wallet).map_err(|s| anyhow::anyhow!(s))?;

        let client = RpcClient::new(
            vec![Url::parse(rpc_url)?],
            everscale_rpc_client::ClientOptions::default(),
        )
        .await?;

        let address = compute_address(&keypair.public, wtype, 0);

        let state = match client.get_contract_state(&address, None).await? {
            Some(contract) => contract,
            None => {
                bail!(
                    "No EverWallet exists. You should send at least 1 EVER to {}",
                    address
                )
            }
        };

        Ok(Self {
            address,
            state,
            keypair,
            client,
        })
    }

    pub async fn new_from_mnemonic(mnemonic: &str, wallet: &str, rpc_url: &str) -> Result<Self> {
        let keypair = derive_from_phrase(mnemonic, nekoton::crypto::MnemonicType::Labs(0))?;

        let wtype = WalletType::from_str(wallet).map_err(|s| anyhow::anyhow!(s))?;

        let client = RpcClient::new(
            vec![Url::parse(rpc_url)?],
            everscale_rpc_client::ClientOptions::default(),
        )
        .await?;

        let address = compute_address(&keypair.public, wtype, 0);

        let state = match client.get_contract_state(&address, None).await? {
            Some(contract) => contract,
            None => {
                bail!(
                    "No EverWallet exists. You should send at least 1 EVER to {}",
                    address
                )
            }
        };

        Ok(Self {
            address,
            state,
            keypair,
            client,
        })
    }

    pub async fn prepare_ever_wallet_transfer(
        &self,
        amount: u64,
        destination: MsgAddressInt,
        body: Option<SliceData>,
    ) -> Result<(ton_types::Cell, Box<dyn UnsignedMessage>)> {
        let gift = Gift {
            flags: 3,
            bounce: true,
            destination,
            amount,
            body,
            state_init: None,
        };

        let expiration = Expiration::Timeout(DEFAULT_EXPIRATION_TIMEOUT);

        let action = nekoton::core::ton_wallet::ever_wallet::prepare_transfer(
            &SimpleClock,
            &self.keypair.public,
            &self.state.account,
            self.address.clone(),
            vec![gift],
            expiration,
        )?;

        let unsigned_message = match action {
            TransferAction::Sign(message) => message,
            TransferAction::DeployFirst => {
                bail!("EverWallet unreachable action")
            }
        };

        // Sign with null signature to extract payload later
        let signed_message = unsigned_message.sign(&[0_u8; 64])?;
        let mut data = signed_message.message.body().trust_me();

        let first_bit = data.get_next_bit()?;
        assert!(first_bit);

        // Skip null signature
        data.move_by(SIGNATURE_LENGTH * 8)?;

        let payload = data.into_cell();

        Ok((payload, unsigned_message))
    }

    pub async fn prepare_token_body(
        &self,
        tokens: BigUint,
        destination: &MsgAddressInt,
        notify: bool,
        payload: ton_types::Cell,
    ) -> Result<SliceData> {
        let (function_token, input_token) =
            MessageBuilder::new(tip3_1::token_wallet_contract::transfer())
                .arg(BigUint128(tokens)) // amount
                .arg(destination) // recipient owner wallet
                .arg(BigUint128(INITIAL_BALANCE.into())) // deployWalletValue
                .arg(self.address.clone()) // remainingGasTo
                .arg(notify) // notify
                .arg(payload) // payload
                .build();

        SliceData::load_builder(function_token.encode_internal_input(&input_token)?)
    }
}

#[derive(Clone, Copy, Default)]
#[allow(dead_code)]
pub struct SignTransactionMeta {
    chain_id: Option<u32>,
    workchain_id: Option<u8>,
    current_wallet_type: Option<WalletType>,
}

impl SignTransactionMeta {
    pub fn new(
        chain_id: Option<u32>,
        workchain_id: Option<u8>,
        current_wallet_type: Option<WalletType>,
    ) -> Self {
        Self {
            chain_id,
            workchain_id,
            current_wallet_type,
        }
    }
}
