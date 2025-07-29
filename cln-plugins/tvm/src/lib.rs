



pub mod abi;
pub mod htlc;
pub mod model;
pub mod rpc;
pub mod wallet;

#[cfg(test)]
pub mod test;
#[cfg(test)]
pub mod tests;

#[macro_export]
macro_rules! network {
    // Pattern for matching inputs
    ($val:expr) => {
        if cfg!(feature = "ever") {
            concat!("ever", $val)
        } else {
            if cfg!(feature = "venom") {
                concat!("venom", $val)
            } else {
                if cfg!(feature = "ton") {
                    concat!("ton", $val)
                } else {
                    // default value
                    concat!("ever", $val)
                }
            }
        }
    };
}
