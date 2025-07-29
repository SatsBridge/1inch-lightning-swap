use anyhow::{bail, Result};
use bitcoin::Address;
use bitcoincore_rpc::{Auth, Client, RpcApi};
use futures::FutureExt;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use port_selector::random_free_tcp_port;
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use bitcoin::address::NetworkChecked;
use tempdir::TempDir;

fn setup_btc_node(port: u16, rpc_port: u16) -> Result<(Child, TempDir)> {
    println!(
        "Starting regtest node on ports: {}, {} (RPC)",
        port, rpc_port
    );
    let tmp_dir = TempDir::new("regtest-data").expect("temporary data dir created");

    let binding = Command::new("bitcoind");

    let mut cmd = binding;

    cmd.arg("-regtest")
        .arg("-server")
        .arg("-rpcuser=regtest")
        .arg("-rpcpassword=regtest")
        .arg("-fallbackfee=0.000002")
        .arg(format!("-port={port}"))
        .arg(format!("-rpcport={rpc_port}"))
        .arg(format!("-datadir={}", tmp_dir.path().to_str().unwrap()));

    let cmd_str = format!("{:?}", cmd).replace("\"", "");

    if let Ok(node_handle) = cmd.stdout(Stdio::null()).spawn() {
        println!("Launched Bitcoind {}:\n{:?}\n", node_handle.id(), cmd_str);

        Ok((node_handle, tmp_dir))
    } else {
        bail!("Bitcoind command didn't start");
    }
}

pub fn teardown_btc_node(mut node_handle: Child) {
    println!("Teardown regtest node");
    signal::kill(Pid::from_raw(node_handle.id() as i32), Signal::SIGTERM).unwrap();
    node_handle.wait().expect("Node terminated");
}

pub async fn setup_btc_node_ready(port: u16, rpc_port: u16) -> Result<(Child, Client, TempDir)> {
    let (node_handle, temp_dir) = setup_btc_node(port, rpc_port)?;

    let rpc_url = format!("http://127.0.0.1:{rpc_port}/wallet/default");
    let client = Client::new(
        &rpc_url,
        Auth::UserPass("regtest".to_owned(), "regtest".to_owned()),
    )
    .expect("Node client");

    match wait_for_btc_node(&client).await {
        Err(e) => {
            teardown_btc_node(node_handle);
            panic!("Node failure: {e}")
        }
        Ok(_) => {}
    };

    match client.create_wallet("default", None, None, None, None) {
        Ok(_) => {}
        Err(e) => {
            teardown_btc_node(node_handle);
            panic!("Cannot create default wallet: {}", e)
        }
    }

    println!("Created Bitcoin Core wallet");
    Ok((node_handle, client, temp_dir))
}

pub async fn wait_for_btc_node(client: &Client) -> Result<()> {
    println!("Bitcoin Core liveness check...");
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(5000)).await;
        // it is not important what address, really
        // "generate" method fails so we use generate_to_address
        let addr: Address<NetworkChecked> = Address::from_str("bcrt1qsdzqt93xsyewdjvagndw9523m27e52er5ca7hm").unwrap().assume_checked();
        let res = client.generate_to_address(101, &addr)?;
        println!("{:?}", res);
        let blocks = client.get_block_count()?;
        println!("Generated {} blocks", blocks);

        return Ok(())
    }
    bail!("Could not establish connection with Bitcoin Core")
}

pub async fn generate_to_address(client: &Client, address: Address<NetworkChecked>) {
    client
        .generate_to_address(101, &address)
        .expect("generate to address failed");
}

pub async fn run_btc_test<F, Fut>(test_body: F) -> Result<()>
where
    F: FnOnce(Client) -> Fut,
    Fut: Future<Output = ()>,
{
    let _ = env_logger::builder().is_test(true).try_init();
    let node_port = random_free_tcp_port().expect("available port");
    let node_rpc_port = random_free_tcp_port().expect("available port");
    let (node_handle, client, _) = setup_btc_node_ready(node_port, node_rpc_port).await?;
    let res = AssertUnwindSafe(test_body(client)).catch_unwind().await;
    teardown_btc_node(node_handle);
    assert!(res.is_ok());
    Ok(())
}
