use anyhow::{bail, Context, Error, Result};

use log::{debug, error, info};


use std::time::{Duration};
use std::{str::FromStr};
use tokio::sync::broadcast::Sender;

use tokio::time::{self};

use cln_plugin::Plugin;
use cln_tvm::model::{
    Balance, HTLCRoutingRequest, HtlcForwarderState, Notification, PluginState, TokenBalance,
    TokenSettleHTLC,
};
use cln_tvm::rpc::{make_rpc_path, pay_invoice};

use cln_rpc::model::responses::PayResponse;


use nekoton::core::models::{TokenWalletVersion};

use nekoton_contracts::tip3_any::{
    RootTokenContractDetails, RootTokenContractState, TokenWalletContractState,
};
//use nekoton::core::token_wallet::{RootTokenContractState, TokenWalletContractState};

use nekoton_abi::PackAbiPlain;
use nekoton_abi::{pack_into_cell, MessageBuilder};

use nekoton_utils::now_sec_u64;
use nekoton_utils::{SimpleClock, TrustMe};

use cln_tvm::wallet::tvm_wallet::{SignTransactionMeta, Wallet};
use serde::Serialize;



use bigdecimal::num_bigint::{BigInt};
use bigdecimal::BigDecimal;



use rust_decimal::prelude::{FromPrimitive, ToPrimitive};
use rust_decimal::Decimal;
use ton_block::{GetRepresentationHash, MsgAddressInt};
use ton_types::{SliceData, UInt256};

use ed25519_dalek::{Signer};

use rand::distributions::Alphanumeric;
use rand::Rng;
use sha2::digest::Output;
use sha2::{Digest, Sha256};

use crate::network;
use cln_tvm::htlc::{htlc_forwarder_contract, HTLC};
use cln_tvm::model::SwapError::{InconsistentInputs};
use cln_tvm::wallet::tvm_wallet::{
    ATTACHED_AMOUNT, DEFAULT_ABI_VERSION,
};

#[derive(Serialize)]
pub struct HtlcContractError {
    address: String,
    receiver: String,
    hashlock: String,
    message: String,
}

pub async fn tvm_channel(
    plugin: Plugin<PluginState>,
    notification_sender: Sender<Notification>,
) -> Result<(), Error> {
    let mut notification_receiver = notification_sender.subscribe();
    debug!("Subscribed to notifications, sleep for 7 sec...");
    time::sleep(Duration::from_secs(7)).await;
    debug!("Reading plugin options");
    let sleep_time = match plugin.option_str(network!("-worker-sleep"))? {
        Some(v) => v.as_i64().unwrap().to_owned() as u64,
        _ => return Err(std::fmt::Error.into()),
    };
    let phrase = match plugin.option_str(network!("-seed"))? {
        Some(v) => v.as_str().unwrap().to_owned(),
        _ => return Err(std::fmt::Error.into()),
    };
    // token contract address
    let token_root = match plugin.option_str(network!("-token"))? {
        Some(v) => v.as_str().unwrap().to_owned(),
        _ => return Err(std::fmt::Error.into()),
    };
    let htlc = match plugin.option_str(network!("-htlc"))? {
        Some(v) => v.as_str().unwrap().to_owned(),
        _ => return Err(std::fmt::Error.into()),
    };
    let _timelock_sec = match plugin.option_str(network!("-htlc-timelock"))? {
        Some(v) => v.as_i64().unwrap().to_owned(),
        _ => return Err(std::fmt::Error.into()),
    };
    let rpc_url = match plugin.option_str(network!("-rpc"))? {
        Some(v) => v.as_str().unwrap().to_owned(),
        _ => return Err(std::fmt::Error.into()),
    };
    let swap_fee = match plugin.option_str(network!("-swap-fee"))? {
        Some(v) => v.as_i64().unwrap().to_owned() as u64,
        _ => 999_u64, // fallback swap fee
    };
    debug!("Re-creating wallet instance");
    let wallet = Wallet::new_from_mnemonic(&phrase, "EverWallet", rpc_url.as_str()).await?;

    debug!("Loading token details: {token_root}");

    let token_root = MsgAddressInt::from_str(token_root.as_str())?;

    let root_contract = wallet
        .client
        .get_contract_state(&token_root, None)
        .await?
        .trust_me();

    let state = RootTokenContractState(root_contract.as_context(&SimpleClock));

    let RootTokenContractDetails {
        symbol,
        decimals,
        version,
        name,
        ..
    } = state.guess_details()?;

    debug!("Token data: {name}, {symbol}, decimals {decimals}");
    let token_address = state.get_wallet_address(version, &wallet.address)?;
    debug!("Token wallet address {token_address}");

    let htlc_address = MsgAddressInt::from_str(&htlc)?;

    let htlc_state = wallet
        .client
        .get_contract_state(&htlc_address, None)
        .await?;

    match htlc_state {
        Some(c) => {
            let raw_state = HTLC(c.as_context(&SimpleClock)).get_details()?;
            let forwarder_state = match HtlcForwarderState::from_tokens(raw_state.clone()) {
                Ok(s) => s,
                Err(e) => {
                    debug!("Raw contract state {:?}", raw_state);
                    bail!("Couldnt parse state: {e:?}. Worker stops")
                }
            };
            if token_root != forwarder_state.token_root {
                bail!(
                    "Expected token root {} do not correspond to HTLC token root {}",
                    token_root,
                    forwarder_state.token_root
                );
            }
        }
        None => {
            bail!("Account state {} not found", htlc_address);
        }
    }
    /*
    debug!("Ethereum RPC provider chain {chain_id} / block {block_number}");
    debug!("Ethereum Token contract {erc20} info: {decimals} decimals");
    debug!("HTLC Token contract {htlc}");
    */
    info!("Checks completed. Starting TVM Channel Manager loop, sleep interval {sleep_time}");
    loop {
        match tokio::time::timeout(
            Duration::from_secs(sleep_time),
            notification_receiver.recv(),
        )
        .await
        {
            Ok(Ok(Notification::GetForwarderState(..))) => {
                let htlc_state = wallet
                    .client
                    .get_contract_state(&htlc_address, None)
                    .await?;
                match htlc_state {
                    Some(c) => {
                        let raw_state = HTLC(c.as_context(&SimpleClock)).get_details()?;
                        match HtlcForwarderState::from_tokens(raw_state.clone()) {
                            Ok(s) => {
                                match notification_sender.send(Notification::HtlcForwarderState(s))
                                {
                                    Ok(_) => debug!("Sent back forwarder state {}", htlc_address),
                                    Err(e) => error!("Couldnt send notification back: {e:?}"),
                                };
                            }
                            Err(e) => {
                                debug!("Raw contract state {:?}", raw_state);
                                error!("Couldnt parse state: {e:?}")
                            }
                        };
                    }
                    None => {
                        info!("Account state {} not found", htlc_address);
                    }
                }
            }
            Ok(Ok(Notification::TokenIncomingHTLC(r))) => {
                // This allows for expansion of functionality or narrowing it down
                info!("Received request for sending tokens {token_root} via HTLC {htlc_address}",);
                let requested_token_root = token_root.clone();

                let requested_root_contract = wallet
                    .client
                    .get_contract_state(&requested_token_root, None)
                    .await?
                    .trust_me();

                let requested_root_state =
                    RootTokenContractState(requested_root_contract.as_context(&SimpleClock));

                let RootTokenContractDetails {
                    symbol: some_symbol,
                    decimals: some_decimals,
                    version: some_version,
                    name: some_name,
                    ..
                } = requested_root_state.guess_details()?;

                let amount = (r.token_amount.clone()
                    * BigDecimal::new(BigInt::from(1), -(some_decimals as i64)))
                .with_scale(0)
                .into_bigint_and_exponent()
                .0
                .to_biguint()
                .trust_me();

                debug!("Sending {some_version} token with data: {some_name}, {some_symbol}, decimals {some_decimals}");
                let token_address =
                    requested_root_state.get_wallet_address(version, &wallet.address)?;
                debug!("Node's token wallet address {token_address}");

                let counterparty = r.receiver;

                debug!(
                    "Destination wallet {}, amount {}, converted {}",
                    counterparty, r.token_amount, amount
                );
                match wallet
                    .client
                    .get_contract_state(&counterparty, None)
                    .await?
                {
                    Some(contract) => {
                        debug!(
                            "Destination EverWallet account {} exists",
                            contract.account.addr
                        );

                        let timelock = now_sec_u64() + r.expire_in;

                        info!("Timelock: {}", timelock.clone());

                        let hashlock = UInt256::from_slice(&r.hashlock);

                        let htlc_request = HTLCRoutingRequest {
                            incoming: true,
                            counterparty,
                            hashlock,
                            timelock,
                        }
                        .pack();

                        let payload = pack_into_cell(&htlc_request, DEFAULT_ABI_VERSION).unwrap();

                        let token_body = wallet
                            .prepare_token_body(amount, &htlc_address, true, payload)
                            .await?;

                        let (payload, unsigned_message) = wallet
                            .prepare_ever_wallet_transfer(
                                ATTACHED_AMOUNT,
                                token_address,
                                Some(token_body),
                            )
                            .await?;

                        let _meta = SignTransactionMeta::default();

                        let _boc = ton_types::serialize_toc(&payload)?;

                        let signature = wallet.keypair.sign(unsigned_message.hash());
                        let signed_message =
                            unsigned_message.sign(&nekoton::crypto::Signature::from(signature))?;

                        let message_hash = signed_message.message.hash()?.to_hex_string();

                        match notification_sender
                            .send(Notification::MessageHash(message_hash.clone()))
                        {
                            Ok(_) => debug!("Sent back message hash {}", message_hash),
                            Err(e) => error!("Couldnt send notification back: {e:?}"),
                        };

                        let status = wallet
                            .client
                            .send_message(
                                signed_message.message,
                                everscale_rpc_client::SendOptions::default(),
                            )
                            .await?;

                        info!("Send status: {:?}", status);
                    }
                    None => {
                        error!(
                            "Destination account state not found. You should send at least 1 EVER to {}",
                            counterparty
                        );
                    }
                }
            }
            Ok(Ok(Notification::TokenRefundHTLC(..))) => {
                let (function_token, input_token) =
                    MessageBuilder::new(htlc_forwarder_contract::refund()).build();

                let body = SliceData::load_builder(
                    function_token
                        .encode_internal_input(&input_token)
                        .with_context(|| {
                            format!(
                                "Failed to encode_internal_input of function: {:?}",
                                function_token
                            )
                        })?,
                )?;
                /*
                let expiration = Expiration::Timeout(DEFAULT_EXPIRATION_TIMEOUT);

                let everwallet_contract = wallet.client.get_contract_state(&wallet.address, None).await?.unwrap();

                // External message

                let action = nekoton::core::ton_wallet::ever_wallet::prepare_transfer(
                    &SimpleClock,
                    &wallet.keypair.public,
                    &everwallet_contract.account,
                    wallet.address.clone(),
                    vec![Gift {
                        flags: 3,
                        bounce: true,
                        destination: htlc_address.clone(),
                        amount: ATTACHED_AMOUNT,
                        body: Some(body),
                        state_init: None,
                    }],
                    expiration,
                )?;

                let unsigned_message = match action {
                    TransferAction::Sign(message) => message,
                    TransferAction::DeployFirst => {
                        bail!("EverWallet unreachable action")
                    }
                };
                */
                // Internal
                let (payload, unsigned_message) = wallet
                    .prepare_ever_wallet_transfer(ATTACHED_AMOUNT, htlc_address.clone(), Some(body))
                    .await?;

                let _meta = SignTransactionMeta::default();

                let _boc = ton_types::serialize_toc(&payload)?;

                let signature = wallet.keypair.sign(unsigned_message.hash());
                let signed_message =
                    unsigned_message.sign(&nekoton::crypto::Signature::from(signature))?;

                let message_hash = signed_message.message.hash()?.to_hex_string();

                match notification_sender.send(Notification::MessageHash(message_hash.clone())) {
                    Ok(_) => debug!("Sent back message hash {}", message_hash),
                    Err(e) => error!("Couldnt send notification back: {e:?}"),
                };

                let status = wallet
                    .client
                    .send_message(
                        signed_message.message,
                        everscale_rpc_client::SendOptions::default(),
                    )
                    .await?;

                info!("Send status: {:?}", status);
            }
            Ok(Ok(Notification::TokenSettleHTLC(r))) => {
                let preimage_uint = UInt256::from_slice(&r.preimage);

                let (function_token, input_token) =
                    MessageBuilder::new(htlc_forwarder_contract::settle())
                        .arg(preimage_uint)
                        .build();

                let body = SliceData::load_builder(
                    function_token
                        .encode_internal_input(&input_token)
                        .with_context(|| {
                            format!(
                                "Failed to encode_internal_input of function: {:?}",
                                function_token
                            )
                        })?,
                )?;

                let (payload, unsigned_message) = wallet
                    .prepare_ever_wallet_transfer(ATTACHED_AMOUNT, htlc_address.clone(), Some(body))
                    .await?;

                let _meta = SignTransactionMeta::default();

                let _boc = ton_types::serialize_toc(&payload)?;

                let signature = wallet.keypair.sign(unsigned_message.hash());
                let signed_message =
                    unsigned_message.sign(&nekoton::crypto::Signature::from(signature))?;

                let message_hash = signed_message.message.hash()?.to_hex_string();

                match notification_sender.send(Notification::MessageHash(message_hash.clone())) {
                    Ok(_) => debug!("Sent back message hash {}", message_hash),
                    Err(e) => error!("Couldnt send notification back: {e:?}"),
                };

                let status = wallet
                    .client
                    .send_message(
                        signed_message.message,
                        everscale_rpc_client::SendOptions::default(),
                    )
                    .await?;

                info!("Send status: {:?}", status);
            }
            Ok(Ok(Notification::TokenOutgoingHTLC(r))) => {
                let amount = (r.amount_sat as u128) * (10_u128.pow(decimals.into()));
                let timelock = now_sec_u64() + r.expire;

                let destination = r.receiver;

                let hashlock_input = match r.hashlock {
                    None => {
                        let preimage = generate_random_hex(32);
                        info!("Preimage generated: {}", preimage);
                        let sec_bytes = hex::decode(preimage)?;
                        let hash_bytes = compute_sha256(&sec_bytes);
                        UInt256::from_slice(&hash_bytes)
                    }
                    Some(h) => UInt256::from_slice(&h),
                };

                info!(
                    "An outgoing HTLC request for a hashlock: {}",
                    hex::encode(hashlock_input)
                );

                let (function_token, input_token) =
                    MessageBuilder::new(htlc_forwarder_contract::route())
                        .arg(destination.clone())
                        .arg(amount)
                        .arg(hashlock_input)
                        .arg(timelock)
                        .build();

                let body = SliceData::load_builder(
                    function_token
                        .encode_internal_input(&input_token)
                        .with_context(|| {
                            format!(
                                "Failed to encode_internal_input of function: {:?}",
                                function_token
                            )
                        })?,
                )?;

                let (payload, unsigned_message) = wallet
                    .prepare_ever_wallet_transfer(ATTACHED_AMOUNT, htlc_address.clone(), Some(body))
                    .await?;

                let _meta = SignTransactionMeta::default();

                let _boc = ton_types::serialize_toc(&payload)?;

                let signature = wallet.keypair.sign(unsigned_message.hash());
                let signed_message =
                    unsigned_message.sign(&nekoton::crypto::Signature::from(signature))?;

                let message_hash = signed_message.message.hash()?.to_hex_string();

                match notification_sender.send(Notification::MessageHash(message_hash.clone())) {
                    Ok(_) => debug!("Sent back message hash {}", message_hash),
                    Err(e) => error!("Couldnt send notification back: {e:?}"),
                };

                let status = wallet
                    .client
                    .send_message(
                        signed_message.message,
                        everscale_rpc_client::SendOptions::default(),
                    )
                    .await?;

                info!("Send status: {:?}", status);
            }
            Ok(Ok(Notification::TokenPayAndSettleIncoming(pr))) => {
                // First, check state
                let mut hashlock = [0u8; 32];
                hashlock.copy_from_slice(&pr.hashlock);
                let hashlock_str = hex::encode(hashlock);
                let invoice_sat = pr.invoice_msat / 1000_u64;
                // TODO: swapfee must be dynamic
                let invoice_plus_fee = invoice_sat + swap_fee;

                info!(
                    "Received PayAndRedeem request for hash {}. Checking contract",
                    hashlock_str
                );
                info!("Amount {invoice_sat} sat");

                let htlc_state = wallet
                    .client
                    .get_contract_state(&htlc_address, None)
                    .await?;

                match htlc_state {
                    Some(c) => {
                        info!("Checking state of the contract {htlc_address}");
                        let raw_state = HTLC(c.as_context(&SimpleClock)).get_details()?;

                        let forwarder_state =
                            match HtlcForwarderState::from_tokens(raw_state.clone()) {
                                Ok(s) => s,
                                Err(e) => {
                                    debug!("Raw contract state {:?}", raw_state);
                                    bail!("Couldnt parse state: {e:?}")
                                }
                            };

                        debug!("Contract state {:?}", forwarder_state);
                        //TODO: BigDecimals
                        let state_amount_scaled =
                            forwarder_state.amount / (10_u64.pow(decimals.into()));
                        if forwarder_state.hashlock != hashlock {
                            let state_hashlock_str = hex::encode(forwarder_state.hashlock);
                            info!(
                                "Contract state hash {} diverges with provided hash {}",
                                state_hashlock_str, hashlock_str
                            );
                            notification_sender.send(Notification::SwapError(
                                InconsistentInputs(state_hashlock_str, hashlock_str),
                            ))?;
                        } else if state_amount_scaled != invoice_plus_fee {
                            let state_amount_str = state_amount_scaled.to_string();
                            let invoice_amount_str = invoice_sat.to_string();
                            info!(
                                "Different amounts contract's {} and invoice's {}",
                                state_amount_str, invoice_amount_str
                            );
                            notification_sender.send(Notification::SwapError(
                                InconsistentInputs(state_amount_str, invoice_amount_str),
                            ))?;
                        } else {
                            info!("All checks passed");
                            let rpc_path = make_rpc_path(plugin.clone());

                            match pay_invoice(&rpc_path, pr.bolt11.clone()).await {
                                Ok(PayResponse {
                                    payment_preimage, ..
                                }) => {
                                    info!("Settlement confirmed, preimage revealed");
                                    //TODO: it probably doesn't capture MessageHash
                                    notification_sender.send(Notification::TokenSettleHTLC(
                                        TokenSettleHTLC {
                                            preimage: payment_preimage.to_vec(),
                                        },
                                    ))?;
                                }
                                Err(e) => {
                                    error!("Payment failed {:?}", e);
                                }
                            };
                        }
                    }
                    None => {
                        info!("Account state {} not found", htlc_address);
                    }
                }
                // Finished checking state
                // Second, pay invoice
            }
            Ok(Ok(Notification::WithdrawToken(w))) => {
                let requested_root_contract = wallet
                    .client
                    .get_contract_state(&w.token_root, None)
                    .await?
                    .trust_me();

                let requested_root_state =
                    RootTokenContractState(requested_root_contract.as_context(&SimpleClock));

                let RootTokenContractDetails {
                    symbol: some_symbol,
                    decimals: some_decimals,
                    version: some_version,
                    name: some_name,
                    ..
                } = requested_root_state.guess_details()?;

                let amount = (w.token_amount.clone()
                    * BigDecimal::new(BigInt::from(1), -(some_decimals as i64)))
                .with_scale(0)
                .into_bigint_and_exponent()
                .0
                .to_biguint()
                .trust_me();

                debug!("Sending {some_version} token with data: {some_name}, {some_symbol}, decimals {some_decimals}");
                let token_address =
                    requested_root_state.get_wallet_address(version, &wallet.address)?;
                debug!("Node's token wallet address {token_address}");
                let destination = w.receiver;
                debug!(
                    "Destination wallet {}, amount {}, converted {}",
                    destination, w.token_amount, amount
                );
                match wallet.client.get_contract_state(&destination, None).await? {
                    Some(contract) => {
                        debug!(
                            "Destination EverWallet account {} exists",
                            contract.account.addr
                        );
                        let payload: ton_types::Cell = Default::default();
                        let token_body = wallet
                            .prepare_token_body(amount, &destination, false, payload)
                            .await?;

                        let (payload, unsigned_message) = wallet
                            .prepare_ever_wallet_transfer(
                                ATTACHED_AMOUNT,
                                token_address,
                                Some(token_body),
                            )
                            .await?;

                        let _meta = SignTransactionMeta::default();

                        let _boc = ton_types::serialize_toc(&payload)?;

                        let signature = wallet.keypair.sign(unsigned_message.hash());
                        let signed_message =
                            unsigned_message.sign(&nekoton::crypto::Signature::from(signature))?;

                        let message_hash = signed_message.message.hash()?.to_hex_string();

                        match notification_sender
                            .send(Notification::MessageHash(message_hash.clone()))
                        {
                            Ok(_) => debug!("Sent back message hash {}", message_hash),
                            Err(e) => error!("Couldnt send notification back: {e:?}"),
                        };

                        let status = wallet
                            .client
                            .send_message(
                                signed_message.message,
                                everscale_rpc_client::SendOptions::default(),
                            )
                            .await?;

                        info!("Send status: {:?}", status);
                    }
                    None => {
                        error!(
                            "Destination account state not found. You should send at least 1 EVER to {}",
                            destination
                        );
                    }
                }
            }
            Ok(Ok(Notification::Withdraw(w))) => {
                let amount = (w.amount.clone() * BigDecimal::new(BigInt::from(1), -9_i64))
                    .to_u64()
                    .trust_me();

                info!("Sending to address {} coins {}", w.address, w.amount);

                let destination = w.address;

                match wallet.client.get_contract_state(&destination, None).await? {
                    Some(contract) => {
                        debug!(
                            "Destination EverWallet account {} exists",
                            contract.account.addr
                        );
                        let (payload, unsigned_message) = wallet
                            .prepare_ever_wallet_transfer(amount, destination, None)
                            .await?;

                        let _boc = ton_types::serialize_toc(&payload)?;

                        let _meta = SignTransactionMeta::default();

                        let signature = wallet.keypair.sign(unsigned_message.hash());
                        let signed_message =
                            unsigned_message.sign(&nekoton::crypto::Signature::from(signature))?;

                        let message_hash = signed_message.message.hash()?.to_hex_string();

                        match notification_sender
                            .send(Notification::MessageHash(message_hash.clone()))
                        {
                            Ok(_) => debug!("Sent back message hash {}", message_hash),
                            Err(e) => error!("Couldnt send notification back: {e:?}"),
                        };

                        let status = wallet
                            .client
                            .send_message(
                                signed_message.message,
                                everscale_rpc_client::SendOptions::default(),
                            )
                            .await?;

                        info!("Send status: {:?}", status);
                    }
                    None => {
                        error!(
                            "Destination account state not found. You should send at least 1 EVER to {}",
                            destination
                        );
                    }
                }
            }
            Ok(Ok(Notification::GetAddress())) => {
                match notification_sender.send(Notification::Address(wallet.address.to_string())) {
                    Ok(_) => debug!(
                        "Wallet address has been sent back {}",
                        wallet.address.to_string()
                    ),
                    Err(e) => error!("Couldnt send notification back: {e:?}"),
                };
            }
            Ok(Ok(Notification::GetBalance())) => {
                let ever_wallet_contract = wallet
                    .client
                    .get_contract_state(&wallet.address, None)
                    .await?;
                let ever_balance = match ever_wallet_contract {
                    Some(contract) => {
                        let mut ever_balance =
                            Decimal::from_u128(contract.account.storage.balance.grams.as_u128())
                                .trust_me();
                        ever_balance.set_scale(9_u32)?;
                        debug!("Balance: {} EVER", ever_balance);
                        ever_balance
                    }
                    None => {
                        error!(
                            "Account {} hasn't been deployed",
                            wallet.address.to_string()
                        );
                        Decimal::from(-1e16 as i64)
                    }
                };
                let token_contract = wallet
                    .client
                    .get_contract_state(&token_address, None)
                    .await?;
                let token_balance = match token_contract {
                    Some(token_contract) => {
                        let token_contract_state =
                            TokenWalletContractState(token_contract.as_context(&SimpleClock));
                        let token_balance =
                            token_contract_state.get_balance(TokenWalletVersion::Tip3)?;
                        let balance_decimal = Decimal::new(
                            token_balance.to_i64().trust_me(),
                            decimals as u32,
                        );
                        info!("Balance: {} {}", balance_decimal, symbol);
                        balance_decimal
                    }
                    None => {
                        info!("Token account haven't deployed yet");
                        Decimal::from(-1e16 as i64)
                    }
                };
                match notification_sender.send(Notification::Balance(Balance {
                    ever: ever_balance,
                    tokens: vec![TokenBalance {
                        symbol: symbol.clone(),
                        name: name.clone(),
                        decimals,
                        balance: token_balance,
                    }],
                })) {
                    Ok(_) => debug!(
                        "Wallet balance has been sent back {} - {}",
                        wallet.address.to_string(),
                        ever_balance
                    ),
                    Err(e) => error!("Couldnt send notification back: {e:?}"),
                }
            }
            Ok(Ok(Notification::GasPrice(..))) => {}
            _ => {
                if notification_sender.is_empty() {
                    debug!("Queue is empty. Sleeping for {}s", sleep_time);
                    time::sleep(Duration::from_secs(sleep_time)).await;
                } else {
                    debug!(
                        "Skipped {} messages awaiting processing",
                        notification_sender.len()
                    );
                }
            }
        }
    }
}

fn generate_random_hex(length: usize) -> String {
    let random_bytes: Vec<u8> = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .collect();

    hex::encode(random_bytes)
}

fn compute_sha256(data: &[u8]) -> Output<Sha256> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize()
}
