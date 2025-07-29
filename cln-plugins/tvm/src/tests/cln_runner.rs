use port_selector::random_free_tcp_port;
use std::future::Future;
use futures::FutureExt;
use std::panic::AssertUnwindSafe;
use std::process::{Child, Command, Stdio};
use bitcoincore_rpc::{Auth, Client, RpcApi};

use anyhow::{anyhow, bail};
use anyhow::Result;
use tempdir::TempDir;

use cln_rpc::{model::requests::GetinfoRequest, ClnRpc};
use std::sync::Arc;

use crate::tests::btc_runner::{setup_btc_node_ready, teardown_btc_node};

use std::env;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use bitcoin::Address;
use bitcoin::address::NetworkChecked;
use cln_rpc::model::requests::{ConnectRequest, FundchannelRequest, NewaddrRequest};
use cln_rpc::primitives::{Amount, AmountOrAll};

fn compiled_binary_path() -> Result<PathBuf, String> {
    // Get the current working directory (project root)
    let current_dir = env::current_dir().map_err(|e| e.to_string())?;

    // Get the build profile: debug or release
    let profile = env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());

    // Get the project name from Cargo.toml metadata
    let project_name = env::var("CARGO_PKG_NAME")
        .unwrap_or_else(|_| "unknown_project".to_string());

    // Construct the binary path
    let binary_path = current_dir
        .join("target")
        .join(&profile)
        .join(&project_name);

    if binary_path.exists() {
        Ok(binary_path)
    } else {
        Err(format!(
            "Compiled binary not found at {}",
            binary_path.display()
        ))
    }
}

fn setup_cln_backend(btc_rpc_port: u16, port: u16, rpc_port: u16) -> Result<(Child, TempDir)> {
    println!(
        "Starting regtest Core Lightning node on ports: {} and {} (RPC), Bitcoind port {}",
        port, rpc_port, btc_rpc_port,
    );
    let tmp_dir = TempDir::new("cln-regtest-data").expect("temporary data dir created");

    let plugin_path = match compiled_binary_path() {
        Ok(path) => path ,
        Err(err) => panic!("Error: {}", err),
    };

    println!("Compiled plugin binary path: {}", plugin_path.display());

    let mnemonic = match env::var("EVER_MNEMONIC") {
        Ok(value) => value,
        Err(e) => panic!("Failed to get environment variable EVER_MNEMONIC: {}", e),
    };

    let binding = Command::new("lightningd");

    let mut cmd = binding;

    cmd.arg("--disable-plugin=offers")
        .arg("--disable-plugin=fetchinvoice")
        .arg("--disable-plugin=bookkeeper")
        .arg("--disable-plugin=cln-grpc")
        .arg("--disable-plugin=keysend")
        .arg("--disable-plugin=topology")
        .arg("--network=regtest")
        .arg("--bitcoin-rpcuser=regtest")
        .arg("--bitcoin-rpcpassword=regtest")
        .arg(format!("--bitcoin-rpcport={btc_rpc_port}"))
        .arg("--funding-confirms=1")
        .arg("--developer")
        .arg("--dev-bitcoind-poll=1")
        .arg("--dev-fast-gossip")
        .arg("--dev-no-htlc-timeout")
        .arg("--htlc-maximum-msat=2000sat")
        .arg("--log-level=debug")
        .arg("--log-file=log")
        .arg(format!("--addr=127.0.0.1:{port}"))
        .arg(format!("--bind-addr=127.0.0.1:{rpc_port}"))
        .arg(format!("--lightning-dir={}", tmp_dir.path().to_str().unwrap()))
        .arg("--dev-force-privkey=0000000000000000000000000000000000000000000000000000000000000001")
        .arg("--dev-force-bip32-seed=0000000000000000000000000000000000000000000000000000000000000001")
        .arg("--dev-force-channel-secrets=0000000000000000000000000000000000000000000000000000000000000010/0000000000000000000000000000000000000000000000000000000000000011/0000000000000000000000000000000000000000000000000000000000000012/0000000000000000000000000000000000000000000000000000000000000013/0000000000000000000000000000000000000000000000000000000000000014/FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
        .arg(format!("--plugin={}", plugin_path.display()))
        .arg("--ever-worker-sleep=1")
        .arg("--ever-native-limit=1")
        .arg("--ever-token-limit=100")
        .arg("--ever-htlc-timelock=600")
        .arg("--ever-event-callback=http://0.0.0.0:5000/network/ethereum/events")
        .arg(format!("--ever-seed={mnemonic}"))
        .arg("--ever-rpc=https://extension-api.broxus.com/rpc")
        .arg("--ever-token=0:34eefc8c8fb2b1e8da6fd6c86c1d5bcee1893bb81d34b3a085e301f2fba8d59c")
        .arg("--ever-htlc=0:1a796587ec8b635e1a1e26d1a502cbd4674dd8ee37f4a3db78a30c25aeacb8ee")
        .arg("--ever-swap-fee=555");

    let cmd_str = format!("{:?}", cmd).replace("\"", "");

    if let Ok(node_handle) = cmd.stdout(Stdio::null()).spawn() {
        println!("Launched Lightningd Backend {}:\n{:?}\n", node_handle.id(), cmd_str);

        Ok((node_handle, tmp_dir))
    } else {
        panic!("Lightningd command didn't start");
    }
}

fn setup_cln_peernode(btc_rpc_port: u16, port: u16, rpc_port: u16) -> Result<(Child, TempDir)> {
    println!(
        "Starting regtest Core Lightning node on ports: {} and {} (RPC), Bitcoind port {}",
        port, rpc_port, btc_rpc_port,
    );
    let tmp_dir = TempDir::new("cln-regtest-data").expect("temporary data dir created");

    let plugin_path = match compiled_binary_path() {
        Ok(path) => path ,
        Err(err) => bail!("Error: {}", err),
    };

    println!("Compiled plugin binary path: {}", plugin_path.display());

    let mnemonic = match env::var("EVER_MNEMONIC") {
        Ok(value) => value,
        Err(e) =>panic!("Failed to get environment variable EVER_MNEMONIC: {}", e),
    };

    let binding = Command::new("lightningd");

    let mut cmd = binding;

    cmd.arg("--disable-plugin=offers")
        .arg("--disable-plugin=fetchinvoice")
        .arg("--disable-plugin=bookkeeper")
        .arg("--disable-plugin=cln-grpc")
        .arg("--disable-plugin=keysend")
        .arg("--disable-plugin=topology")
        .arg("--network=regtest")
        .arg("--bitcoin-rpcuser=regtest")
        .arg("--bitcoin-rpcpassword=regtest")
        .arg(format!("--bitcoin-rpcport={btc_rpc_port}"))
        .arg("--funding-confirms=1")
        .arg("--developer")
        .arg("--dev-bitcoind-poll=1")
        .arg("--dev-fast-gossip")
        .arg("--dev-no-htlc-timeout")
        .arg("--htlc-maximum-msat=2000sat")
        .arg("--log-level=debug")
        .arg("--log-file=log")
        .arg(format!("--addr=127.0.0.1:{port}"))
        .arg(format!("--bind-addr=127.0.0.1:{rpc_port}"))
        .arg(format!("--lightning-dir={}", tmp_dir.path().to_str().unwrap()))
        .arg("--dev-force-privkey=0000000000000000000000000000000000000000000000000000000000000002")
        .arg("--dev-force-bip32-seed=0000000000000000000000000000000000000000000000000000000000000002")
        .arg("--dev-force-channel-secrets=0000000000000000000000000000000000000000000000000000000000000011/0000000000000000000000000000000000000000000000000000000000000111/0000000000000000000000000000000000000000000000000000000000000112/0000000000000000000000000000000000000000000000000000000000000113/0000000000000000000000000000000000000000000000000000000000000114/FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA")
        .arg(format!("--plugin={}", plugin_path.display()))
        .arg("--ever-worker-sleep=1")
        .arg("--ever-native-limit=1")
        .arg("--ever-token-limit=100")
        .arg("--ever-htlc-timelock=600")
        .arg("--ever-event-callback=http://0.0.0.0:5000/network/ethereum/events")
        .arg(format!("--ever-seed={mnemonic}"))
        .arg("--ever-rpc=https://extension-api.broxus.com/rpc")
        .arg("--ever-token=0:34eefc8c8fb2b1e8da6fd6c86c1d5bcee1893bb81d34b3a085e301f2fba8d59c")
        .arg("--ever-htlc=0:1a796587ec8b635e1a1e26d1a502cbd4674dd8ee37f4a3db78a30c25aeacb8ee")
        .arg("--ever-swap-fee=555");

    let cmd_str = format!("{:?}", cmd).replace("\"", "");

    if let Ok(node_handle) = cmd.stdout(Stdio::null()).spawn() {
        println!("Launched Lightningd Peer {}:\n{:?}\n", node_handle.id(), cmd_str);

        Ok((node_handle, tmp_dir))
    } else {
        panic!("Lightningd command didn't start");
    }
}

async fn setup_cln_backend_ready(
    btc_client: &Client,
    btc_rpc_port: u16,
    port: u16,
    rpc_port: u16,
) -> Result<(Child, PathBuf)> {
    btc_client
        .get_blockchain_info()
        .expect("no connection with Bitcoind");

    let (node_handle, temp_dir) = setup_cln_backend(btc_rpc_port, port, rpc_port)?;
    let cln_socket = temp_dir.path().join("regtest/lightning-rpc");

    Ok((node_handle, cln_socket))
}

async fn setup_cln_peernode_ready(
    btc_client: &Client,
    btc_rpc_port: u16,
    port: u16,
    rpc_port: u16,
) -> Result<(Child, PathBuf)> {
    btc_client
        .get_blockchain_info()
        .expect("no connection with Bitcoind");

    let (node_handle, temp_dir) = setup_cln_peernode(btc_rpc_port, port, rpc_port)?;
    let cln_socket = temp_dir.path().join("regtest/lightning-rpc");

    Ok((node_handle, cln_socket))
}


async fn wait_for_cln_node(socket: PathBuf) -> Result<()> {
    // it becomes just ping function if there is a connection
    let mut cln = ClnRpc::new(&socket).await?;
    for _ in 0..100 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let res = cln
            .call_typed(&GetinfoRequest {})
            .await?;
        println!("{:?}", res);
    }
    panic!("Could not establish connection with Lightning node")
}


pub async fn run_cln_test<F, Fut>(test_body: F) -> Result<()>
where
    F: FnOnce(Client, Child, Child) -> Fut,
    Fut: Future<Output = ()>,
{
    let _ = env_logger::builder().is_test(true).try_init();

    let btc_port = random_free_tcp_port().expect("available port");
    let btc_rpc_port = random_free_tcp_port().expect("available port");
    let (btc_handle, btc_client) = match setup_btc_node_ready(btc_port, btc_rpc_port).await
    {
        Ok((h, c, _)) => (h, c),
        Err(e) => {
            bail!(e)
        }
    };
    println!("Started Bitcoin Core");
    let cln_port = random_free_tcp_port().expect("available port");
    let cln_rpc_port = random_free_tcp_port().expect("available port");
    let (cln_back_client, cln_back_socket) =
        match  setup_cln_backend_ready(&btc_client, btc_rpc_port, cln_port, cln_rpc_port).await {
            Ok((h, s)) => (h, s),
            Err(e) => {
                teardown_btc_node(btc_handle);
                bail!(e)
            }
        };
    let _ = wait_for_cln_node(cln_back_socket).await;
    println!("Started Backend CLN");
    let cln_peer_port = random_free_tcp_port().expect("available port");
    let cln_peer_rpc_port = random_free_tcp_port().expect("available port");
    let (cln_peer_client, cln_peer_socket) =
        match  setup_cln_peernode_ready(&btc_client, btc_rpc_port, cln_peer_port, cln_peer_rpc_port).await {
            Ok((h, s)) => (h, s),
            Err(e) => {
                teardown_btc_node(btc_handle);
                bail!(e)
            }
        };
    let _ = wait_for_cln_node(cln_peer_socket).await;
    println!("Started Peer CLN");

    let res = AssertUnwindSafe(test_body(btc_client, cln_back_client, cln_peer_client))
        .catch_unwind()
        .await;

    teardown_btc_node(btc_handle);
    assert!(res.is_ok());
    Ok(())
}


pub async fn run_cln_test_external_core<F, Fut>(test_body: F) -> Result<()>
    where
        F: FnOnce(Client, ClnRpc, ClnRpc) -> Fut,
        Fut: Future<Output = ()>,
{
    let _ = env_logger::builder().is_test(true).try_init();

    let btc_rpc_port = 38463;

    let rpc_port = 38463;
    let rpc_url = format!("http://127.0.0.1:{rpc_port}/wallet/default");

    let btc_client = Client::new(
        &rpc_url,
        Auth::UserPass("regtest".to_owned(), "regtest".to_owned()),
    )
        .expect("Node client");

    println!("Started Core Client");
    let cln_port = random_free_tcp_port().expect("available port");
    let cln_rpc_port = random_free_tcp_port().expect("available port");
    let (_, cln_back_socket) =
        match  setup_cln_backend_ready(&btc_client, btc_rpc_port, cln_port, cln_rpc_port).await {
            Ok((h, s)) => (h, s),
            Err(e) => {
                bail!(e)
            }
        };
    println!("Started Backend CLN");
    let cln_peer_port = random_free_tcp_port().expect("available port");
    let cln_peer_rpc_port = random_free_tcp_port().expect("available port");
    let (_, cln_peer_socket) =
        match  setup_cln_peernode_ready(&btc_client, btc_rpc_port, cln_peer_port, cln_peer_rpc_port).await {
            Ok((h, s)) => (h, s),
            Err(e) => {
                bail!(e)
            }
        };
    println!("Started Peer CLN");

    tokio::time::sleep(std::time::Duration::from_millis(5000)).await;

    let mut cln_back_client = ClnRpc::new(&cln_back_socket).await?;
    let mut cln_peer_client = ClnRpc::new(&cln_peer_socket).await?;

    let new_addr = cln_back_client.call_typed(&NewaddrRequest { addresstype: None }).await.unwrap();
    let funding_address = new_addr.bech32.unwrap();
    let funding_addr: Address<NetworkChecked> = Address::from_str(&funding_address).unwrap().assume_checked();
    btc_client.generate_to_address(101, &funding_addr).expect("Funding generation failed");

    tokio::time::sleep(std::time::Duration::from_millis(10000)).await;

    let peer_info = cln_peer_client.call_typed(&GetinfoRequest {}).await.unwrap();

    if let Some(binding) = &peer_info.binding {
        cln_back_client
            .call_typed(&ConnectRequest {
                id: peer_info.id.to_string(),
                host: binding[0].clone().address.clone(),
                port: binding[0].clone().port,
            })
            .await
            .expect("Node connection failed");
    } else {
        panic!("Peer node binding is missing");
    }
    // Step 5: Open a channel
    let open_channel = cln_back_client
        .call_typed(&FundchannelRequest {
            announce: Some(true),
            close_to: None,
            compact_lease: None,
            feerate: None,
            minconf: None,
            mindepth: None,
            push_msat: None,
            request_amt: None,
            reserve: None,
            channel_type: None,
            id: peer_info.id,
            amount: AmountOrAll::Amount(Amount::from_sat(100_000)),
            utxos: None,
        })
        .await
        .expect("Channel funding failed");
    println!("{:?}", open_channel);
    // Confirm the channel
    btc_client.generate_to_address(3, &funding_addr).expect("Blocks to confirm channel failed");

    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;

    let res = AssertUnwindSafe(test_body(btc_client, cln_back_client, cln_peer_client))
        .catch_unwind()
        .await;

    assert!(res.is_ok());
    Ok(())
}

