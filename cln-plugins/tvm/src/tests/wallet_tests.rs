use crate::wallet::tvm_wallet::Wallet;
use anyhow::Result;

use serde_json::json;
use std::fs;
use std::str::FromStr;

use tempfile::tempdir;
use ton_block::MsgAddressInt;

#[tokio::test]
async fn test_wallet_creation() -> Result<()> {
    let temp_dir = tempdir()?;
    let keystore_path = temp_dir.path().join("keystore.json");

    let mnemonic = "pioneer fever hazard scan install wise reform corn bubble leisure amazing note"
        .to_string();

    let keystore_content = json!({
        "mnemonic": mnemonic,
    });

    fs::write(&keystore_path, keystore_content.to_string())?;

    let wallet_type = "EverWallet";
    let rpc_url = "https://extension-api.broxus.com/rpc";

    //let wallet =
    //    Wallet::new_from_keystore(keystore_path.to_str().unwrap(), wallet_type, rpc_url).await;

    let wallet =
        Wallet::new_from_mnemonic(mnemonic.as_str(), wallet_type, rpc_url).await;

    assert!(wallet.is_ok());
    let wallet = wallet.unwrap();
    assert_eq!(
        wallet.keypair.secret.as_bytes(),
        &[
            227, 113, 239, 29, 114, 102, 252, 71, 179, 13, 73, 220, 136, 104, 97, 89, 143, 9, 226,
            230, 41, 77, 127, 5, 32, 254, 154, 164, 96, 17, 78, 81
        ]
    );
    assert_eq!(
        wallet.address,
        MsgAddressInt::from_str(
            "0:7046c17280f32aa995f5b97c189daab2eb71c133d89fa488b50abde7549835c7"
        )
        .unwrap()
    );
    temp_dir.close()?;
    Ok(())
}
