use anyhow::{anyhow, Error};
use cln_plugin::Plugin;
use std::path::{Path, PathBuf};

use hex;

use bigdecimal::{BigDecimal};
use log::{debug, error, info};
use serde_json::json;
use std::{str::FromStr, time::Duration};

use tokio::time;

use crate::model::{
    Notification, TokenIncomingHTLC, TokenPayAndSettleIncoming, TokenSettleHTLC, Withdraw,
    WithdrawToken,
};
use crate::model::{PluginState, TokenOutgoingHTLC};
use crate::network;

use cln_rpc::{
    model::{
        requests::{DecodepayRequest, PayRequest},
        responses::{DecodepayResponse, PayResponse},
    },
    ClnRpc, Request, Response,
};
use cln_rpc::model::requests::StopRequest;
use cln_rpc::model::responses::StopResponse;


use tokio::sync::broadcast::Sender;

use ton_block::MsgAddressInt;


pub async fn get_swap_fee(
    plugin: Plugin<PluginState>,
    _args: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let swap_fee = match plugin.option_str(network!("-swap-fee"))? {
        Some(v) => v.as_i64().unwrap().to_owned() as u64,
        _ => 999_u64, // fallback swap fee
    };
    Ok(json!({
            "code": 0,
            "message": swap_fee,
    }))
}

pub async fn get_gas(
    plugin: Plugin<PluginState>,
    _args: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let n = Notification::GasPrice(0_u64);
    match plugin.state().channel.send(n.clone()) {
        Ok(_) => {
            debug!("Sent notification GasPrice");
        }
        Err(e) => {
            error!("Couldnt send notification: {e:?}");
            return Ok(json!({
                "code": 1,
                "message": format!("{n} request failed due to {e}")
            }));
        }
    };
    let mut notification_receiver = plugin.state().channel.subscribe();

    match time::timeout(Duration::from_secs(60_u64), notification_receiver.recv()).await {
        Ok(Ok(Notification::GasPrice(gas))) => Ok(json!({
            "code": 0,
            "message": gas,
        })),
        _ => Ok(json!({
            "code": 1,
            "message": "No response received on gas request"
        })),
    }
}

pub async fn get_wallet(
    plugin: Plugin<PluginState>,
    _args: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let n = Notification::GetAddress();
    match plugin.state().channel.send(n.clone()) {
        Ok(_) => {
            debug!("Sent notification Address");
        }
        Err(e) => {
            error!("Couldnt send notification: {e:?}");
            return Ok(json!({
                "code": 1,
                "message": format!("{n} request failed due to {e}")
            }));
        }
    };

    let mut notification_receiver = plugin.state().channel.subscribe();

    match time::timeout(Duration::from_secs(60_u64), notification_receiver.recv()).await {
        Ok(Ok(Notification::Address(address))) => Ok(json!({
            "code": 0,
            "message": address,
        })),
        _ => Ok(json!({
            "code": 1,
            "message": "No response received on address request"
        })),
    }
}

pub async fn get_balance(
    plugin: Plugin<PluginState>,
    _args: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let n = Notification::GetBalance();
    match plugin.state().channel.send(n.clone()) {
        Ok(_) => {
            debug!("Sent notification for getting Balance");
        }
        Err(e) => {
            error!("Couldnt send notification: {e:?}");
            return Ok(json!({
                "code": 1,
                "message": format!("{n} request failed due to {e}")
            }));
        }
    };

    let mut notification_receiver = plugin.state().channel.subscribe();

    match time::timeout(Duration::from_secs(60_u64), notification_receiver.recv()).await {
        Ok(Ok(Notification::Balance(b))) => Ok(json!({
            "code": 0,
            "message": b,
        })),
        _ => Ok(json!({
            "code": 1,
            "message": "No response received on balance request"
        })),
    }
}

pub async fn get_htlc_state(
    plugin: Plugin<PluginState>,
    _args: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let n = Notification::GetForwarderState();
    match plugin.state().channel.send(n.clone()) {
        Ok(_) => {
            debug!("Sent notification for getting GetForwarderState");
        }
        Err(e) => {
            error!("Couldnt send notification: {e:?}");
            return Ok(json!({
                "code": 1,
                "message": format!("{n} request failed due to {e}")
            }));
        }
    };

    let mut notification_receiver = plugin.state().channel.subscribe();

    match time::timeout(Duration::from_secs(60_u64), notification_receiver.recv()).await {
        Ok(Ok(Notification::HtlcForwarderState(s))) => Ok(json!({
            "code": 0,
            "message": s,
        })),
        _ => Ok(json!({
            "code": 1,
            "message": "Failed to receive forwarder state"
        })),
    }
}

pub async fn tvm_withdraw(
    plugin: Plugin<PluginState>,
    args: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let valid_arg_keys = vec!["address", "amount"];

    let new_args = assign_arguments(&args, &valid_arg_keys);
    match new_args {
        Ok(a) => {
            if !a["address"].is_string() {
                return Ok(invalid_input_error("address is not a string"));
            }
            if !a["amount"].is_f64() {
                return Ok(invalid_input_error("amount is not a rational number"));
            } // needed only as long as CLN plugin can't parse argument into string

            let amount = BigDecimal::from_str(&a["amount"].as_f64().unwrap().to_string())?;

            let address = match MsgAddressInt::from_str(a["address"].to_string().trim_matches('"'))
            {
                Ok(a) => a,
                Err(_) => {
                    return Ok(json!({
                        "code": 1,
                        "message": format!("Cant parse address in MsgAddressInt")
                    }))
                }
            };

            info!(
                "Sending notification {:?} / {:?} to Worker",
                address, amount
            );
            let n = Notification::Withdraw(Withdraw { address, amount });
            match plugin.state().channel.send(n.clone()) {
                Ok(_) => {
                    debug!("Sent notification Withdraw");
                    wait_for_message_hash(plugin.state().channel.clone()).await
                }
                Err(e) => {
                    error!("Couldnt send notification: {e:?}");
                    Ok(json!({
                        "code": 1,
                        "message": format!("{n} failed due to {e}")
                    }))
                }
            }
        }
        Err(e) => Ok(e),
    }
}

pub async fn token_withdraw(
    plugin: Plugin<PluginState>,
    args: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let valid_arg_keys = vec!["receiver", "token_root", "amount"];

    let new_args = assign_arguments(&args, &valid_arg_keys);
    match new_args {
        Ok(a) => {
            if !a["receiver"].is_string() {
                return Ok(invalid_input_error("Sender wallet address is not a string"));
            }
            if !a["token_root"].is_string() {
                return Ok(invalid_input_error("Token root (address) is not a string"));
            }
            if !a["amount"].is_f64() {
                return Ok(invalid_input_error("amount is not a rational number"));
            } // needed only as long as CLN plugin can't parse argument into string

            let token_amount = BigDecimal::from_str(&a["amount"].as_f64().unwrap().to_string())?;

            let receiver =
                match MsgAddressInt::from_str(a["receiver"].to_string().trim_matches('"')) {
                    Ok(a) => a,
                    Err(_) => {
                        return Ok(json!({
                            "code": 1,
                            "message": format!("Cant parse address in MsgAddressInt")
                        }))
                    }
                };

            let token_root =
                match MsgAddressInt::from_str(a["token_root"].to_string().trim_matches('"')) {
                    Ok(a) => a,
                    Err(_) => {
                        return Ok(json!({
                            "code": 1,
                            "message": format!("Cant parse address in MsgAddressInt")
                        }))
                    }
                };

            // Native amount
            info!(
                "Sending token withdraw request to Channel Manager: {} {} of {}",
                receiver, token_amount, token_root
            );
            let n = Notification::WithdrawToken(WithdrawToken {
                receiver,
                token_root,
                token_amount,
            });
            match plugin.state().channel.send(n.clone()) {
                Ok(_) => {
                    debug!("Sent notification WithdrawToken");
                    wait_for_message_hash(plugin.state().channel.clone()).await
                }
                Err(e) => {
                    error!("Couldnt send notification: {e:?}");
                    Ok(json!({
                        "code": 1,
                        "message": format!("{n} failed due to {e}")
                    }))
                }
            }
        }
        Err(e) => Ok(e),
    }
}

pub async fn into_tvm_channel(
    plugin: Plugin<PluginState>,
    args: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let valid_arg_keys = vec!["receiver", "hashlock", "token", "amount"];
    // newContract(receiver, hashlock, timelock, tokenContract, amount) - a
    // sender calls this to create a new HTLC on a given token (tokenContract)
    // for a given amount. A 32 byte contract id is returned
    let new_args = assign_arguments(&args, &valid_arg_keys);
    match new_args {
        Ok(a) => {
            if !a["receiver"].is_string() {
                return Ok(invalid_input_error("receiver is not a string"));
            }
            if !a["hashlock"].is_string() {
                return Ok(invalid_input_error("hashlock is not a string"));
            }
            if !a["amount"].is_u64() {
                return Ok(invalid_input_error("token amount is not an integer number"));
            } // needed only as long as CLN plugin can't parse argument into string
            if !a["token"].is_string() {
                return Ok(invalid_input_error("token address is not a string"));
            } // remove later since channel implementation do not need token
              //if !a["expiry"].is_u64() {
              //    return Ok(invalid_input_error("HTLC expiration is not an integer number"));
              //}
            let token_amount = BigDecimal::from_str(&a["amount"].as_u64().unwrap().to_string())?;

            let receiver =
                match MsgAddressInt::from_str(a["receiver"].to_string().trim_matches('"')) {
                    Ok(a) => a,
                    Err(_) => {
                        return Ok(json!({
                            "code": 1,
                            "message": format!("Cant parse address in MsgAddressInt")
                        }))
                    }
                };

            //let expire_in = a["expiry"].as_u64().unwrap();
            let expire_in = 600_u64;

            let hashlock_str = a["hashlock"].as_str().unwrap();

            let hashlock = match hex::decode(hashlock_str) {
                Ok(b) => b,
                Err(_e) => {
                    return Ok(json!({
                        "code": 1,
                        "message": "Non-hex payment_hash"
                    }))
                }
            };

            info!(
                "Sending incoming Token HTLC notification {:?} / {} / {:?} to Worker",
                receiver, hashlock_str, token_amount
            );
            let n = Notification::TokenIncomingHTLC(TokenIncomingHTLC {
                receiver,
                hashlock,
                expire_in,
                token_amount,
            });
            match plugin.state().channel.send(n.clone()) {
                Ok(_) => {
                    debug!("Sent notification TokenIncomingHTLC");
                    wait_for_message_hash(plugin.state().channel.clone()).await
                }
                Err(e) => {
                    error!("Couldnt send notification: {e:?}");
                    Ok(json!({
                        "code": 1,
                        "message": format!("{n} failed due to {e}")
                    }))
                }
            }
        }
        Err(e) => Ok(e),
    }
}

pub async fn from_tvm_channel(
    plugin: Plugin<PluginState>,
    args: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let valid_arg_keys = vec!["receiver", "hashlock", "token", "amount"];
    // newContract(receiver, hashlock, timelock, tokenContract, amount) - a
    // sender calls this to create a new HTLC on a given token (tokenContract)
    // for a given amount. A 32 byte contract id is returned
    let new_args = assign_arguments(&args, &valid_arg_keys);
    match new_args {
        Ok(a) => {
            if !a["receiver"].is_string() {
                return Ok(invalid_input_error("receiver is not a string"));
            }
            if !a["hashlock"].is_string() {
                return Ok(invalid_input_error("hashlock is not a string"));
            }
            if !a["amount"].is_u64() {
                return Ok(invalid_input_error("token amount is not an integer number"));
            } // needed only as long as CLN plugin can't parse argument into string
            if !a["token"].is_string() {
                return Ok(invalid_input_error("token address is not a string"));
            } // remove later since channel implementation do not need token
              //if !a["expiry"].is_u64() {
              //    return Ok(invalid_input_error("HTLC expiration is not an integer number"));
              //}
              // TODO: to consider converting into BigDecimal with 12 decimals
              //let token_amount = BigDecimal::from_str(&a["amount"].as_f64().unwrap().to_string())?;

            let amount_sat = a["amount"].as_u64().unwrap();
            let expire = 600_u64; //a["expire"].as_u64().unwrap();

            let receiver =
                match MsgAddressInt::from_str(a["receiver"].to_string().trim_matches('"')) {
                    Ok(a) => a,
                    Err(_) => {
                        return Ok(json!({
                            "code": 1,
                            "message": format!("Cant parse address in MsgAddressInt")
                        }))
                    }
                };

            let hashlock = match hex::decode(a["hashlock"].as_str().unwrap()) {
                Ok(b) => b,
                Err(_e) => {
                    return Ok(json!({
                        "code": 1,
                        "message": "Non-hex payment_hash"
                    }))
                }
            };
            info!(
                "Sending outgoing Token HTLC notification {:?} / {} / {:?} to Worker",
                receiver,
                hex::encode(hashlock.clone()),
                amount_sat
            );
            let n = Notification::TokenOutgoingHTLC(TokenOutgoingHTLC {
                receiver,
                hashlock: Some(hashlock),
                preimage: None,
                amount_sat,
                expire,
            });
            match plugin.state().channel.send(n.clone()) {
                Ok(_) => {
                    debug!("Sent notification WithdrawToken");
                    wait_for_message_hash(plugin.state().channel.clone()).await
                }
                Err(e) => {
                    error!("Couldnt send notification: {e:?}");
                    Ok(json!({
                        "code": 1,
                        "message": format!("WithdrawToken failed due to {e}")
                    }))
                }
            }
        }
        Err(e) => Ok(e),
    }
}

pub async fn settle_token_htlc(
    plugin: Plugin<PluginState>,
    args: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let valid_arg_keys = vec!["preimage"];
    let new_args = assign_arguments(&args, &valid_arg_keys);
    match new_args {
        Ok(a) => {
            if !a["preimage"].is_string() {
                return Ok(invalid_input_error("preimage is not a string"));
            }
            let preimage = match hex::decode(a["preimage"].as_str().unwrap()) {
                Ok(b) => b,
                Err(_e) => {
                    return Ok(json!({
                        "code": 1,
                        "message": "Non-hex preimage"
                    }))
                }
            };
            info!("Sending settle Token HTLC notification");
            let n = Notification::TokenSettleHTLC(TokenSettleHTLC { preimage });
            match plugin.state().channel.send(n.clone()) {
                Ok(_) => {
                    debug!("Sent notification TokenSettleHTLC");
                    wait_for_message_hash(plugin.state().channel.clone()).await
                }
                Err(e) => {
                    error!("Couldnt send notification: {e:?}");
                    Ok(json!({
                        "code": 1,
                        "message": format!("{n} HTLC failed due to {e}")
                    }))
                }
            }
        }
        Err(e) => Ok(e),
    }
}

pub async fn refund_token_htlc(
    plugin: Plugin<PluginState>,
    _args: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    info!("Sending refund Token HTLC notification");
    let n = Notification::TokenRefundHTLC();
    match plugin.state().channel.send(n.clone()) {
        Ok(_) => {
            debug!("Sent notification TokenRefundHTLC");
            wait_for_message_hash(plugin.state().channel.clone()).await
        }
        Err(e) => {
            error!("Couldnt send notification: {e:?}");
            Ok(json!({
                "code": 1,
                "message": format!("{n} failed due to {e}")
            }))
        }
    }
}

fn assign_arguments(
    args: &serde_json::Value,
    keys: &Vec<&str>,
) -> Result<serde_json::Value, serde_json::Value> {
    let mut new_args = serde_json::Value::Object(Default::default());
    match args {
        serde_json::Value::Array(a) => {
            if a.len() != keys.len() {
                return Err(invalid_argument_amount(&a.len(), &keys.len()));
            }
            for (idx, arg) in a.iter().enumerate() {
                if idx < keys.len() {
                    new_args[keys[idx]] = arg.clone();
                }
            }
        }
        serde_json::Value::Object(o) => {
            for (k, v) in o.iter() {
                if !keys.contains(&k.as_str()) {
                    return Err(invalid_argument_error(k));
                }
                new_args[k] = v.clone();
            }
        }
        _ => return Err(invalid_input_error(&args.to_string())),
    };
    Ok(new_args.clone())
}

fn invalid_argument_error(arg: &str) -> serde_json::Value {
    json!({
        "code": 1,
        "message": format!("Invalid argument: '{}'", arg)
    })
}

fn invalid_input_error(input: &str) -> serde_json::Value {
    json!({
        "code": 1,
        "message": format!("Invalid input: '{}'", input)
    })
}

fn invalid_argument_amount(size: &usize, needed: &usize) -> serde_json::Value {
    json!({
        "code": 1,
        "message": format!("Provided '{}', needed '{}'", size, needed)
    })
}

pub async fn pay_redeem_token_htlc(
    plugin: Plugin<PluginState>,
    args: serde_json::Value,
) -> Result<serde_json::Value, Error> {
    let valid_arg_keys = vec!["bolt11", "tx"];
    let new_args = assign_arguments(&args, &valid_arg_keys);
    match new_args {
        Ok(a) => {
            // supply it to the channel manager
            if !a["bolt11"].is_string() {
                return Ok(invalid_input_error("bolt11 is not a string"));
            }
            if !a["tx"].is_string() {
                return Ok(invalid_input_error("tx is not a string"));
            }
            let bolt11 = a["bolt11"]
                .to_string()
                .trim_matches(|c: char| !c.is_alphanumeric())
                .to_owned()
                .to_string();

            info!("Decoding and extracting hash from invoice {bolt11}");

            let rpc_path = make_rpc_path(plugin.clone());

            let (hash_str, invoice_msat) = match decode_invoice(&rpc_path, bolt11.clone()).await {
                Ok(DecodepayResponse {
                    payment_hash,
                    amount_msat,
                    ..
                }) => {
                    let amount = match amount_msat {
                        None => {
                            return Ok(json!({
                                "code": 1,
                                "message": "Amountless invoices cant be accepted",
                            }));
                        }
                        Some(a) => a.msat(),
                    };
                    (
                        payment_hash
                            .to_string()
                            .trim_matches(|c: char| !c.is_alphanumeric())
                            .to_owned(),
                        amount,
                    )
                }
                Err(_) => {
                    return Ok(json!({
                        "code": 1,
                        "message": "Impossible to decode BOLT11 invoice",
                    }));
                }
            };

            // decodepay returns a valid payment_hash
            let hashlock = hex::decode(hash_str.clone()).unwrap();

            info!(
                "Sending pay and redeem Token HTLC notification {}",
                hash_str
            );
            let n = Notification::TokenPayAndSettleIncoming(TokenPayAndSettleIncoming {
                hashlock,
                bolt11,
                invoice_msat,
            });
            match plugin.state().channel.send(n.clone()) {
                Ok(_) => Ok(json!({
                    "code": 0,
                    "message": "In settlement"
                })),
                Err(e) => {
                    error!("Couldnt send notification: {e:?}");
                    Ok(json!({
                        "code": 1,
                        "message": format!("{n} failed due to {e}")
                    }))
                }
            }
        }
        Err(e) => Ok(e),
    }
}

pub fn make_rpc_path(plugin: Plugin<PluginState>) -> PathBuf {
    Path::new(&plugin.configuration().lightning_dir).join(plugin.configuration().rpc_file)
}

pub async fn decode_invoice(rpc_path: &PathBuf, bolt1: String) -> Result<DecodepayResponse, Error> {
    let mut rpc = ClnRpc::new(&rpc_path).await?;
    let decoded = rpc
        .call(Request::DecodePay(DecodepayRequest {
            bolt11: bolt1,
            description: None,
        }))
        .await
        .map_err(|e| anyhow!("Error calling decodepay: {:?}", e))?;
    match decoded {
        Response::DecodePay(info) => Ok(info),
        e => Err(anyhow!("Unexpected result in decodepay: {:?}", e)),
    }
}

pub async fn pay_invoice(rpc_path: &PathBuf, bolt1: String) -> Result<PayResponse, Error> {
    let mut rpc = ClnRpc::new(&rpc_path).await?;
    let decoded = rpc
        .call(Request::Pay(PayRequest {
            bolt11: bolt1,
            // https://docs.corelightning.org/reference/lightning-getroute
            riskfactor: Some(100.0),
            // Until retry_for seconds passes (default: 60), the command will keep
            // finding routes and retrying the payment.
            retry_for: Some(300),
            maxfeepercent: Some(1.5),
            // However, a payment may be
            // delayed for up to maxdelay blocks by another node; clients should be
            // prepared for this worst case.
            maxdelay: None,
            label: Some("SatsBridge payment".to_string()),
            // Less critical parameters
            maxfee: None,
            amount_msat: None,
            exemptfee: None,
            localinvreqid: None,
            exclude: None,
            description: None,
            partial_msat: None,
        }))
        .await
        .map_err(|e| anyhow!("Error calling payinvoice: {:?}", e))?;
    match decoded {
        Response::Pay(info) => Ok(info),
        e => Err(anyhow!("Unexpected result in payinvoice: {:?}", e)),
    }
}

pub async fn wait_for_message_hash(
    channel: Sender<Notification>,
) -> Result<serde_json::Value, Error> {
    let mut notification_receiver = channel.subscribe();
    // 60 sec timeout is too small for PayAndRedeem
    match time::timeout(Duration::from_secs(110_u64), notification_receiver.recv()).await {
        Ok(Ok(Notification::MessageHash(m))) => Ok(json!({
            "code": 0,
            "message": m,
        })),
        Ok(Ok(Notification::SwapError(e))) => Ok(json!({
            "code": 1,
            "message": e,
        })),
        Ok(Err(_)) => Ok(json!({
            "code": 1,
            "message": "Received Error from the Worker"
        })),
        Err(_) => Ok(json!({
            "code": 1,
            "message": "Timeout"
        })),
        _ => Ok(json!({
        "code": 1,
        "message": "Unexpected result received from Worker"
        })),
    }
}


pub async fn halt_node(rpc_path: &PathBuf) -> Result<StopResponse, Error> {
    let mut rpc = ClnRpc::new(&rpc_path).await?;
    rpc
        .call_typed(&StopRequest {})
        .await
        .map_err(|e| anyhow!("Error calling stop: {:?}", e))
}
