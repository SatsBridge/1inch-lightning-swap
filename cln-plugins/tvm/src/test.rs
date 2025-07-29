use bitcoin::address::NetworkChecked;
use bitcoin::{Address, Network};
use bitcoincore_rpc::RpcApi;
use cln_rpc::model::requests::{
    ConnectRequest, FundchannelRequest, GetinfoRequest, InvoiceRequest, NewaddrRequest, PayRequest,
    StopRequest,
};
use std::str::FromStr;

use crate::network;
use cln_rpc::model::responses::StopResult::SHUTDOWN_COMPLETE;
use cln_rpc::primitives::{Amount, AmountOrAll, AmountOrAny};
use cln_rpc::{Request, Response};
use serde_json::json;
use crate::model::{Balance};

use crate::tests::btc_runner::run_btc_test;
use crate::tests::cln_runner::run_cln_test_external_core;


#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cln_test_htlc_flows() {
    let _ = run_cln_test_external_core(|btc, mut cln_back, mut cln_peer| async move {
        // Ensure nodes are synced
        let info = btc
            .get_blockchain_info()
            .expect("Failed to fetch blockchain info");
        let n = Network::from_str("regtest").unwrap();
        assert_eq!(info.chain, n);

        let back_info = cln_back.call_typed(&GetinfoRequest {}).await.unwrap();
        let peer_info = cln_peer.call_typed(&GetinfoRequest {}).await.unwrap();
        assert_eq!(back_info.blockheight as u64, info.blocks);
        assert_eq!(peer_info.blockheight as u64, info.blocks);

        //tokio::time::sleep(std::time::Duration::from_millis(10000)).await;

        let swap_fee_res: serde_json::Value = cln_back
            .call_raw(network!("swapfee"), &json!({}))
            .await
            .unwrap();
        println!("Swap fee: {:?}", swap_fee_res);

        let wallet_res: serde_json::Value = cln_back
            .call_raw(network!("wallet"), &json!({}))
            .await
            .unwrap();
        println!("Wallet: {:?}", wallet_res);

        let balance_res: serde_json::Value = cln_back
            .call_raw(network!("balance"), &json!({}))
            .await
            .unwrap();
        println!("Balance: {:?}", balance_res);

        let htlc_res: serde_json::Value = cln_back
            .call_raw(network!("gethtlcstate"), &json!({}))
            .await
            .unwrap();

        // Example
        /*
        let tvm_htlc_req = Request::Custom {
            method: "eversendintotvmchannel".to_string(),
            params: json!({
                "wallet": beta_rpc_path, // Replace with actual wallet identifier
                "hash": payment_hash,
                "amount": 100.000,
                "expiry": 120,
            }),
        };
         */

        // TODO: contribution into CLN_RPC project for more general type
        // let _ : Response = serde_json::from_value(htlc_res.clone()).unwrap();
        println!("State: {:?}", htlc_res);

        // Send a payment from back to peer
        for i in 0..10 {
            let invoice = cln_peer
                .call_typed(&InvoiceRequest {
                    cltv: None,
                    deschashonly: None,
                    expiry: None,
                    preimage: None,
                    exposeprivatechannels: None,
                    fallbacks: None,
                    amount_msat: AmountOrAny::Amount(Amount::from_sat(1_000)),
                    label: format!("test_payment {i}"),
                    description: "Test payment".to_string(),
                })
                .await
                .expect("Failed to create invoice");

            cln_back
                .call_typed(&PayRequest {
                    amount_msat: None,
                    description: None,
                    exemptfee: None,
                    label: None,
                    localinvreqid: None,
                    maxdelay: None,
                    maxfee: None,
                    maxfeepercent: None,
                    partial_msat: None,
                    retry_for: None,
                    riskfactor: None,
                    exclude: None,
                    bolt11: invoice.bolt11,
                })
                .await
                .expect("Payment from back to peer failed");
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }

        // Send a payment back from peer to back
        let invoice_back = cln_back
            .call_typed(&InvoiceRequest {
                cltv: None,
                deschashonly: None,
                expiry: None,
                preimage: None,
                exposeprivatechannels: None,
                fallbacks: None,
                amount_msat: AmountOrAny::Amount(Amount::from_sat(1_000)),
                label: "test_payment_back".to_string(),
                description: "Test payment back".to_string(),
            })
            .await
            .expect("Failed to create invoice");

        cln_peer
            .call_typed(&PayRequest {
                bolt11: invoice_back.bolt11,
                // https://docs.corelightning.org/reference/lightning-getroute
                riskfactor: Some(100.0),
                // Until retry_for seconds passes (default: 60), the command will keep
                // finding routes and retrying the payment.
                retry_for: Some(300),
                maxfeepercent: Some(1.5),
                // However, a payment may be
                // delayed for up to maxdelay blocks by another node; clients should be
                // prepared for this worst case.
                maxdelay: Some(6),
                label: Some("Test payment back".to_string()),
                // Less critical parameters
                maxfee: None,
                amount_msat: None,
                exemptfee: None,
                localinvreqid: None,
                exclude: None,
                description: None,
                partial_msat: None,
            })
            .await
            .expect("Payment from peer to back failed");

        // Shutdown nodes
        let back_stop = cln_back.call_typed(&StopRequest {}).await.unwrap();
        assert_eq!(back_stop.result, Some(SHUTDOWN_COMPLETE));

        let peer_stop = cln_peer.call_typed(&StopRequest {}).await.unwrap();
        assert_eq!(peer_stop.result, Some(SHUTDOWN_COMPLETE));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cln_test_with_channels_and_payments() {
    let _ = run_cln_test_external_core(|btc, mut cln_back, mut cln_peer| async move {
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        // Ensure nodes are synced
        let info = btc
            .get_blockchain_info()
            .expect("Failed to fetch blockchain info");
        let n = Network::from_str("regtest").unwrap();
        assert_eq!(info.chain, n);

        let back_info = cln_back.call_typed(&GetinfoRequest {}).await.unwrap();
        let peer_info = cln_peer.call_typed(&GetinfoRequest {}).await.unwrap();
        assert_eq!(back_info.blockheight as u64, info.blocks);
        assert_eq!(peer_info.blockheight as u64, info.blocks);

        // Send a payment from back to peer
        for i in 0..10 {
            let invoice = cln_peer
                .call_typed(&InvoiceRequest {
                    cltv: None,
                    deschashonly: None,
                    expiry: None,
                    preimage: None,
                    exposeprivatechannels: None,
                    fallbacks: None,
                    amount_msat: AmountOrAny::Amount(Amount::from_sat(1_000)),
                    label: format!("test_payment {i}"),
                    description: "Test payment".to_string(),
                })
                .await
                .expect("Failed to create invoice");

            cln_back
                .call_typed(&PayRequest {
                    amount_msat: None,
                    description: None,
                    exemptfee: None,
                    label: None,
                    localinvreqid: None,
                    maxdelay: None,
                    maxfee: None,
                    maxfeepercent: None,
                    partial_msat: None,
                    retry_for: None,
                    riskfactor: None,
                    exclude: None,
                    bolt11: invoice.bolt11,
                })
                .await
                .expect("Payment from back to peer failed");
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }

        // Send a payment back from peer to back
        let invoice_back = cln_back
            .call_typed(&InvoiceRequest {
                cltv: None,
                deschashonly: None,
                expiry: None,
                preimage: None,
                exposeprivatechannels: None,
                fallbacks: None,
                amount_msat: AmountOrAny::Amount(Amount::from_sat(1_000)),
                label: "test_payment_back".to_string(),
                description: "Test payment back".to_string(),
            })
            .await
            .expect("Failed to create invoice");

        cln_peer
            .call_typed(&PayRequest {
                bolt11: invoice_back.bolt11,
                // https://docs.corelightning.org/reference/lightning-getroute
                riskfactor: Some(100.0),
                // Until retry_for seconds passes (default: 60), the command will keep
                // finding routes and retrying the payment.
                retry_for: Some(300),
                maxfeepercent: Some(1.5),
                // However, a payment may be
                // delayed for up to maxdelay blocks by another node; clients should be
                // prepared for this worst case.
                maxdelay: Some(6),
                label: Some("Test payment back".to_string()),
                // Less critical parameters
                maxfee: None,
                amount_msat: None,
                exemptfee: None,
                localinvreqid: None,
                exclude: None,
                description: None,
                partial_msat: None,
            })
            .await
            .expect("Payment from peer to back failed");

        // Shutdown nodes
        let back_stop = cln_back.call_typed(&StopRequest {}).await.unwrap();
        assert_eq!(back_stop.result, Some(SHUTDOWN_COMPLETE));

        let peer_stop = cln_peer.call_typed(&StopRequest {}).await.unwrap();
        assert_eq!(peer_stop.result, Some(SHUTDOWN_COMPLETE));
    })
    .await;
}

// Check that we have node and API operational
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn core_test() {
    let _ = run_btc_test(|btc| async move {
        let addr: Address<NetworkChecked> =
            Address::from_str("bcrt1qsdzqt93xsyewdjvagndw9523m27e52er5ca7hm")
                .unwrap()
                .assume_checked();
        let res = btc
            .generate_to_address(101, &addr)
            .expect("generate to address failed");
        println!("{:?}", res);

        println!("Running basic Bitcoind test");
        let info = btc.get_blockchain_info().expect("blockchain info");
        println!("{:?}", info);

        let n = Network::from_str("regtest").unwrap();
        assert_eq!(info.chain, n);

        let res = btc
            .generate_to_address(101, &addr)
            .expect("generate to address failed");

        println!("{:?}", res);
    })
    .await;
}
