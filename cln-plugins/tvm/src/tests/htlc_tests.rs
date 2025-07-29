
use anyhow::Result;
use hex;


use sha2::{Digest, Sha256};




use ton_types::UInt256;

#[tokio::test]
async fn test_hashlock_transformations() -> Result<()> {
    let hashlock = hex::decode("9b879e9cea02fc3e077b89a92697414afe7d1b9878786aebe024fe5801ac8b6a")?;
    let hashlock_uint = UInt256::from_slice(&hashlock);

    let preimage = hex::decode("117b64b350051e327a269acffb2d82c9bf91ba536f9b728d7f17a94260abdbcd")?;
    let preimage_uint = UInt256::from_slice(&preimage);

    let mut hasher = Sha256::new();
    hasher.update(&preimage_uint);
    let computed = hasher.finalize();
    let computed_uint = UInt256::from_slice(&computed);

    assert_eq!(computed_uint, hashlock_uint);

    let mut hasher = Sha256::new();
    hasher.update(&preimage);
    let computed = hasher.finalize();

    let computed_uint = UInt256::from_slice(&computed);

    assert_eq!(computed_uint, hashlock_uint);
    Ok(())
}
