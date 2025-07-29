use bitcoincore_rpc::bitcoin::Address;
use bitcoincore_rpc::{Client, RpcApi};
use std::str::FromStr;
use bitcoin::address::NetworkChecked;

use cln_rpc::{ClnRpc};

pub fn fund_node_wallet(client: &Client, block_num: u64, _ln_client: &ClnRpc) {
    //let new_address = ln_client.newaddr(None).expect("Core node address");
    //let str_address = new_address.address.expect("BTC address string");
    let str_address = "test".to_string();
    let address: Address<NetworkChecked> = Address::from_str(str_address.as_str()).expect("BTC address").assume_checked();
    client
        .generate_to_address(block_num, &address)
        .expect("mined blocks");
}
