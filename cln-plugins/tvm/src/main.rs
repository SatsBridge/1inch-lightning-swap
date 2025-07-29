use std::{sync::Arc};

use anyhow::{anyhow, Result};
use cln_plugin::options::{
    DefaultIntegerConfigOption, DefaultStringConfigOption, IntegerConfigOption, StringConfigOption,
};
use cln_plugin::Builder;

use log::{debug, error};
use parking_lot::Mutex;
use tokio::sync::broadcast;

mod channel_manager;

use cln_tvm::model::PluginState;
use cln_tvm::network;
use cln_tvm::rpc::{
    from_tvm_channel, get_balance, get_gas, get_htlc_state, get_swap_fee, get_wallet,
    into_tvm_channel, pay_redeem_token_htlc, refund_token_htlc, settle_token_htlc, token_withdraw,
    tvm_withdraw
};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    debug!("Starting Ethereum Virtual Machine plugin");
    std::env::set_var("CLN_PLUGIN_LOG", "debug");

    let (notification_sender, _) = broadcast::channel(1024);

    let state = PluginState {
        blockheight: Arc::new(Mutex::new(u32::default())),
        channel: notification_sender.clone(),
    };

    let plugin = if let Some(p) = Builder::new(tokio::io::stdin(), tokio::io::stdout())
        .option(DefaultIntegerConfigOption::new_i64_with_default(
            network!("-worker-sleep"),
            5,
            "TVM worker sleep option",
        ))
        .option(DefaultStringConfigOption::new_str_with_default(
            network!("-rpc"),
            "https://extension-api.broxus.com/rpc",
            "RPC API with or without token string for requesting smart-contract data",
        ))
        .option(StringConfigOption::new_str_no_default(
            network!("-seed"),
            "Wallet seed",
        ))
        .option(StringConfigOption::new_str_no_default(
            network!("-token"),
            "Token contract address",
        ))
        .option(StringConfigOption::new_str_no_default(
            network!("-htlc"),
            "Hashed Timelock token contract address",
        ))
        .option(IntegerConfigOption::new_i64_no_default(
            network!("-htlc-timelock"),
            "Token HTLC contract timelock",
        ))
        .option(IntegerConfigOption::new_i64_no_default(
            network!("-native-limit"),
            "ETH token withdtawal limit",
        ))
        .option(IntegerConfigOption::new_i64_no_default(
            network!("-token-limit"),
            "Token token withdtawal limit",
        ))
        .option(DefaultIntegerConfigOption::new_i64_with_default(
            network!("-swap-fee"),
            999,
            "URL for callbacks from worker",
        ))
        .rpcmethod(
            network!("wallet"),
            "Plugin's main wallet address",
            get_wallet,
        )
        .rpcmethod(
            network!("swapfee"),
            "Returns option value that sets swap fees",
            get_swap_fee,
        )
        .rpcmethod(
            network!("withdraw"),
            "Creates, signs and submits an onchain transaction",
            tvm_withdraw,
        )
        .rpcmethod(
            network!("tokenwithdraw"),
            "Creates, signs and submits a TIP3/Jetton onchain transaction",
            token_withdraw,
        )
        .rpcmethod(
            network!("settokenhtlc"),
            "Calls routing method in HTLC contract and initiates routing",
            from_tvm_channel,
        )
        .rpcmethod(
            network!("redeemtokenhtlc"),
            "Redeems TIP3/Jetton tokens from HTLC contract",
            settle_token_htlc,
        )
        .rpcmethod(
            network!("refundtokenhtlc"),
            "Redeems TIP3/Jetton tokens from HTLC contract",
            refund_token_htlc,
        )
        .rpcmethod(
            network!("payredeemtokenhtlc"),
            "Pays an invoice and redeems TIP3/Jetton tokens from HTLC contract",
            pay_redeem_token_htlc,
        )
        .rpcmethod(network!("gas"), "Get gas price estimation", get_gas)
        // newly added functions below
        .rpcmethod(
            network!("balance"),
            "Plugin's main wallet balances in respective network",
            get_balance,
        )
        .rpcmethod(
            network!("gethtlcstate"),
            "Returns actual state of HTLC contract",
            get_htlc_state,
        )
        .rpcmethod(
            network!("sendtochannel"),
            "Creates, signs and submits onchain Token transaction",
            into_tvm_channel,
        )
        .configure()
        .await?
    {
        p
    } else {
        return Ok(());
    };

    if let Ok(plugin) = plugin.start(state).await {
        let pcloned = plugin.clone();
        tokio::spawn(async move {
            match channel_manager::tvm_channel(pcloned.clone(), notification_sender.clone()).await {
                Ok(()) => (),
                Err(e) => {
                    error!("Error in TVM worker: {}", e.to_string());
                    // TODO: make shut down option. Hard shutdown appears like an option that may
                    // lead to issues
                    /*
                    let rpc_path = make_rpc_path(pcloned);
                    match halt_node(&rpc_path).await {
                        Ok(r) => info!("Requested for shutting down, received: {:?}", r),
                        Err(e) => error!("During shut down another error occured {e}"),
                    }
                    */
                }
            };
        });
        plugin.join().await
    } else {
        Err(anyhow!("Error starting the plugin!"))
    }
}
