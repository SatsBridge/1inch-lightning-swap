use std::fmt;
use anyhow::{anyhow, Result};
use bigdecimal::BigDecimal;

use serde::{Deserialize, Serialize, Serializer};
use std::string::String;
use std::{
    collections::{HashMap},
    sync::Arc,
};
use tokio::sync::broadcast::Sender;

use cln_rpc::model::responses::ListinvoicesInvoices;
use parking_lot::Mutex;


use rust_decimal::Decimal;

use ed25519_dalek::Keypair;
use log::{debug};
use nekoton_abi::{PackAbiPlain, UnpackAbiPlain};
use nekoton_utils::serde_address;
use ton_abi::{Function, Token, TokenValue, Uint};
use ton_block::{AccountStuff, MsgAddressInt};
use ton_types::{BuilderData, Cell, UInt256};

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct Contract {
    pub sender: String,
    pub receiver: String,
    pub tokenContract: String,
    pub hashlock: String,
    pub timelock: String,
    pub amount: u64,
    pub expiry: u32,
    pub loop_mutex: Arc<tokio::sync::Mutex<bool>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContractId {
    #[serde(with = "serde_address")]
    pub address: MsgAddressInt,
    pub htlc_id: u64,
}

#[derive(Clone, Debug)]
pub struct TvmInvoice {
    pub state: Contract,
    pub generation: u64,
    pub evm_data: HashMap<ContractId, Contract>,
    pub invoice: ListinvoicesInvoices,
}

#[derive(Clone, Debug)]
pub struct PluginState {
    pub blockheight: Arc<Mutex<u32>>,
    pub channel: Sender<Notification>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Withdraw {
    #[serde(with = "serde_address")]
    pub address: MsgAddressInt,
    pub amount: BigDecimal,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct WithdrawToken {
    #[serde(with = "serde_address")]
    pub receiver: MsgAddressInt,
    #[serde(with = "serde_address")]
    pub token_root: MsgAddressInt,
    // Token native amounts
    pub token_amount: BigDecimal,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TokenIncomingHTLC {
    #[serde(with = "serde_address")]
    pub receiver: MsgAddressInt,
    pub hashlock: Vec<u8>,
    pub expire_in: u64,
    pub token_amount: BigDecimal,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TokenSettleHTLC {
    pub preimage: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TokenOutgoingHTLC {
    #[serde(with = "serde_address")]
    pub receiver: MsgAddressInt,
    pub hashlock: Option<Vec<u8>>,
    pub preimage: Option<Vec<u8>>,
    pub amount_sat: u64,
    pub expire: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TokenPayAndSettleIncoming {
    pub hashlock: Vec<u8>,
    pub invoice_msat: u64,
    pub bolt11: String,
}

pub type GasPrice = u64;
pub type MessageHash = String;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TokenBalance {
    pub symbol: String,
    pub name: String,
    pub decimals: u8,
    pub balance: Decimal,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Balance {
    pub ever: Decimal,
    pub tokens: Vec<TokenBalance>,
}

// TODO: replace get balance
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TotalBalance {
    pub wallet: Balance,
    pub forwarder: Balance,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ForwarderState {
    pub ever: Decimal,
    pub tokens: Vec<TokenBalance>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HtlcForwarderState {
    pub incoming: bool,
    #[serde(with = "serde_address")]
    pub counterparty: MsgAddressInt,
    #[serde(serialize_with = "hex_serialize")]
    pub hashlock: Vec<u8>,
    pub timelock: u64,
    pub amount: u64,
    #[serde(with = "serde_address")]
    pub token_root: MsgAddressInt,
    #[serde(with = "serde_address")]
    pub token_wallet: MsgAddressInt,
}

impl HtlcForwarderState {
    pub fn from_tokens(tokens: Vec<Token>) -> Result<Self> {
        let mut incoming = None;
        let mut counterparty = None;
        let mut hashlock = None;
        let mut timelock = None;
        let mut amount = None;
        let mut token_root = None;
        let mut token_wallet = None;

        for token in tokens {
            debug!("Parsing {}", token.name.as_str());
            debug!("Parsing {}", token.value);
            match token.name.as_str() {
                "incoming" => {
                    incoming = match token.value {
                        TokenValue::Bool(v) => Some(v),
                        _ => None,
                    }
                }
                "counterparty" => {
                    counterparty = match token.value {
                        TokenValue::Address(v) => v.to_msg_addr_int(),
                        _ => None,
                    };
                }
                "hashlock" => {
                    hashlock = match token.value {
                        TokenValue::Uint(v) => Some(v.number.to_bytes_be()),
                        _ => None,
                    };
                }
                "timelock" => {
                    timelock = match token.value {
                        TokenValue::Uint(Uint { number, size: 64 }) => match number.clone().try_into() {
                            Ok(val) => Some(val), // Safely converts to u64 if possible
                            Err(_) => {
                                debug!(
                                    "Failed to convert number {} to u64 in {}",
                                    number,
                                    token.name.as_str()
                                );
                                Some(u64::max_value())
                            }
                        },
                        _ => None,
                    };
                }
                "amount" => {
                    amount = match token.value {
                        TokenValue::Uint(Uint { number, size: 128 }) => match number.clone().try_into() {
                            Ok(val) => Some(val), // Safely converts to u64 if possible
                            Err(_) => {
                                debug!(
                                    "Failed to convert number {} to u64 in {}",
                                    number,
                                    token.name.as_str()
                                );
                                //TODO: critical code change type
                                Some(u64::max_value())
                            }
                        },
                        _ => None,
                    };
                }
                "tokenRoot" => {
                    token_root = match token.value {
                        TokenValue::Address(v) => v.to_msg_addr_int(),
                        _ => None,
                    };
                }
                "tokenWallet" => {
                    token_wallet = match token.value {
                        TokenValue::Address(v) => v.to_msg_addr_int(),
                        _ => None,
                    };
                }
                _ => { /* Ignore unrecognized fields */ }
            }
        }

        Ok(HtlcForwarderState {
            incoming: incoming.ok_or_else(|| anyhow!("Missing 'incoming' field"))?,
            counterparty: counterparty.ok_or_else(|| anyhow!("Missing 'counterparty' field"))?,
            hashlock: hashlock.ok_or_else(|| anyhow!("Missing 'hashlock' field"))?,
            timelock: timelock.ok_or_else(|| anyhow!("Missing 'timelock' field"))?,
            amount: amount.ok_or_else(|| anyhow!("Missing 'amount' field"))?,
            token_root: token_root.ok_or_else(|| anyhow!("Missing 'token_root' field"))?,
            token_wallet: token_wallet.ok_or_else(|| anyhow!("Missing 'token_wallet' field"))?,
        })
    }
    /*
    pub fn from_hashmap(data: HashMap<String, String>) -> Result<Self> {
        let incoming = data.get("incoming")
            .ok_or_else(|| anyhow!("Missing 'incoming' field"))?
            .parse::<bool>()
            .map_err(|_| anyhow!("Failed to parse 'incoming' as bool"))?;

        let counterparty = data.get("counterparty")
            .ok_or_else(|| anyhow!("Missing 'counterparty' field"))?
            .clone();

        let hashlock = data.get("hashlock")
            .ok_or_else(|| anyhow!("Missing 'hashlock' field"))?
            .as_bytes()
            .to_vec();  // or use hex decoding if needed

        let timelock = data.get("timelock")
            .ok_or_else(|| anyhow!("Missing 'timelock' field"))?
            .parse::<u64>()
            .map_err(|_| anyhow!("Failed to parse 'timelock' as u64"))?;

        Ok(HtlcForwarderState {
            incoming,
            counterparty,
            hashlock,
            timelock,
            amount
        })
    }
     */
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SwapError {
    #[error("An error occurred due to inconsistent inputs {0} {1}")]
    InconsistentInputs(String, String),
    #[error("Address can not be parsed")]
    CantParseAddress,
    #[error("Specific error message")]
    SpecificError,
}

/// Used to send messages via broadcast channel to outside workers
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Notification {
    Withdraw(Withdraw),
    WithdrawToken(WithdrawToken),
    TokenIncomingHTLC(TokenIncomingHTLC),
    TokenRefundHTLC(),
    TokenOutgoingHTLC(TokenOutgoingHTLC),
    TokenSettleHTLC(TokenSettleHTLC),
    TokenPayAndSettleIncoming(TokenPayAndSettleIncoming),
    GasPrice(GasPrice),
    GetForwarderState(),
    HtlcForwarderState(HtlcForwarderState),
    GetAddress(),
    Address(String),
    MessageHash(MessageHash),
    GetBalance(),
    Balance(Balance),
    SwapError(SwapError),
}

impl fmt::Display for Notification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Only output variant names without data for `Display`
        let name = match self {
            Notification::Withdraw(_) => "Withdraw",
            Notification::WithdrawToken(_) => "WithdrawToken",
            Notification::TokenIncomingHTLC(_) => "TokenIncomingHTLC",
            Notification::TokenRefundHTLC() => "TokenRefundHTLC",
            Notification::TokenOutgoingHTLC(_) => "TokenOutgoingHTLC",
            Notification::TokenSettleHTLC(_) => "TokenSettleHTLC",
            Notification::TokenPayAndSettleIncoming(_) => "TokenPayAndSettleIncoming",
            Notification::GasPrice(_) => "GasPrice",
            Notification::GetForwarderState() => "GetForwarderState",
            Notification::HtlcForwarderState(_) => "HtlcForwarderState",
            Notification::GetAddress() => "GetAddress",
            Notification::Address(_) => "Address",
            Notification::MessageHash(_) => "MessageHash",
            Notification::GetBalance() => "GetBalance",
            Notification::Balance(_) => "Balance",
            Notification::SwapError(_) => "SwapError",
        };
        write!(f, "{}", name)
    }
}

#[derive(Debug, Clone, PackAbiPlain)]
pub struct HTLCRoutingRequest {
    #[abi(name = "_incoming")]
    pub incoming: bool,
    #[abi(name = "_counterparty", address)]
    pub counterparty: MsgAddressInt,
    #[abi(name = "_hashlock", uint256)]
    pub hashlock: UInt256,
    #[abi(name = "_timelock", uint64)]
    pub timelock: u64,
}

#[derive(PackAbiPlain, UnpackAbiPlain, Debug, Clone)]
pub struct Transfer {
    #[abi]
    pub amount: u128,
    #[abi]
    pub recipient: MsgAddressInt,
    #[abi(name = "deployWalletValue")]
    pub deploy_wallet_value: u128,
    #[abi(name = "remainingGasTo")]
    pub remaining_gas_to: MsgAddressInt,
    #[abi]
    pub notify: bool,
    #[abi]
    pub payload: Cell,
}

pub struct PayloadMeta {
    pub payload: BuilderData,
    pub destination: MsgAddressInt,
}

pub struct SendData {
    pub payload_meta: PayloadMeta,
    pub signer: Keypair,
    pub sender_addr: MsgAddressInt,
}

impl SendData {
    pub fn new(payload_meta: PayloadMeta, signer: Keypair, sender_addr: MsgAddressInt) -> Self {
        Self {
            payload_meta,
            signer,
            sender_addr,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct CreateAccountParams {
    pub nonce: u32,
}

#[derive(Serialize, Deserialize)]
pub struct EverWalletInfo {
    #[serde(rename = "createAccountParams")]
    pub create_account_params: CreateAccountParams,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GenericDeploymentInfo {
    #[serde(with = "serde_address")]
    pub address: MsgAddressInt,
}

pub struct PayloadGenerator {
    pub htlc: AccountStuff,
    pub htlc_fun: Function,
    pub destination: MsgAddressInt,
    pub htlc_request: Vec<Token>,
}

impl PayloadGenerator {
    pub fn generate_payload_meta(&mut self) -> PayloadMeta {
        PayloadMeta {
            payload: self
                .htlc_fun
                .encode_internal_input(&self.htlc_request)
                .unwrap(),
            destination: self.destination.clone(),
        }
    }
}

fn hex_serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let hex_string = if bytes.is_empty() {
        "0".to_string() // Use "0" to represent an empty `hashlock`
    } else {
        hex::encode(bytes)
    };
    serializer.serialize_str(&hex_string)
}
