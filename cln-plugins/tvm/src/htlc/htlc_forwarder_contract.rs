use nekoton_abi::{
    EventBuilder, FunctionBuilder, KnownParamTypePlain, PackAbi,
    PackAbiPlain, UnpackAbiPlain,
};
use once_cell::sync::OnceCell;


use ton_abi::{Param, ParamType};

#[derive(Debug, Clone, PackAbi, UnpackAbiPlain, KnownParamTypePlain)]
pub struct GetDetailsFunctionOutput {
    #[abi(bool)]
    pub incoming: bool,
    #[abi(address)]
    pub counterparty: ton_block::MsgAddressInt,
    #[abi(name = "tokenRoot", address)]
    pub token_root: ton_block::MsgAddressInt,
    #[abi(name = "tokenWallet", address)]
    pub token_wallet: ton_block::MsgAddressInt,
    #[abi(uint128)]
    pub amount: u128,
    #[abi(uint256)]
    pub hashlock: ton_types::UInt256,
    #[abi(uint64)]
    pub timelock: u64,
}

#[derive(Debug, Clone, PackAbi, UnpackAbiPlain, KnownParamTypePlain)]
pub struct SettleFunctionInput {
    #[abi(uint256)]
    pub preimage: ton_types::UInt256,
}

#[derive(Debug, Clone, PackAbi, UnpackAbiPlain, KnownParamTypePlain)]
pub struct TransferFunctionInput {
    #[abi(address)]
    pub destination: ton_block::MsgAddressInt,
    #[abi(uint128)]
    pub amount: u128,
}

#[derive(Debug, Clone, PackAbi, UnpackAbiPlain, KnownParamTypePlain)]
pub struct SettleFunctionOutput {
    #[abi(bool)]
    pub value0: bool,
}

#[derive(Debug, Clone, PackAbiPlain, UnpackAbiPlain, KnownParamTypePlain)]
pub struct RouteFunctionInput {
    #[abi(address)]
    pub counterparty: ton_block::MsgAddressInt,
    #[abi(uint128)]
    pub amount: u128,
    #[abi(uint256)]
    pub hashlock: ton_types::UInt256,
    #[abi(uint64)]
    pub timelock: u64,
}

#[derive(Debug, Clone, PackAbi, UnpackAbiPlain, KnownParamTypePlain)]
pub struct HTLCResetEventInput;

#[derive(Debug, Clone, PackAbi, UnpackAbiPlain, KnownParamTypePlain)]
pub struct HTLCSettleEventInput {
    #[abi(uint256)]
    pub preimage: ton_types::UInt256,
    #[abi(name = "tokenRoot", address)]
    pub token_root: ton_block::MsgAddressInt,
    #[abi(uint128)]
    pub amount: u128,
}

#[derive(Debug, Clone, PackAbi, UnpackAbiPlain, KnownParamTypePlain)]
pub struct HTLCRefundEventInput {
    #[abi(uint256)]
    pub hashlock: ton_types::UInt256,
    #[abi(name = "tokenRoot", address)]
    pub token_root: ton_block::MsgAddressInt,
    #[abi(uint128)]
    pub amount: u128,
}

#[derive(Debug, Clone, PackAbi, UnpackAbiPlain, KnownParamTypePlain)]
pub struct HTLCNewEventInput {
    #[abi(bool)]
    pub incoming: bool,
    #[abi(address)]
    pub counterparty: ton_block::MsgAddressInt,
    #[abi(name = "tokenWallet", address)]
    pub token_wallet: ton_block::MsgAddressInt,
    #[abi(name = "tokenRoot", address)]
    pub token_root: ton_block::MsgAddressInt,
    #[abi(uint128)]
    pub amount: u128,
    #[abi(uint256)]
    pub hashlock: ton_types::UInt256,
    #[abi(uint64)]
    pub timelock: u64,
}

pub fn settle() -> &'static ton_abi::Function {
    static FUNCTION: OnceCell<ton_abi::Function> = OnceCell::new();
    FUNCTION.get_or_init(|| {
        let header = vec![
            Param {
                name: "pubkey".to_string(),
                kind: ParamType::PublicKey,
            },
            Param {
                name: "time".to_string(),
                kind: ParamType::Time,
            },
            Param {
                name: "expire".to_string(),
                kind: ParamType::Expire,
            },
        ];
        let mut builder = FunctionBuilder::new("settle");
        builder = builder
            .abi_version(ton_abi::contract::ABI_VERSION_2_2)
            .headers(header)
            .inputs(SettleFunctionInput::param_type())
            .outputs(SettleFunctionOutput::param_type());
        builder.build()
    })
}

pub fn transfer() -> &'static ton_abi::Function {
    static FUNCTION: OnceCell<ton_abi::Function> = OnceCell::new();
    FUNCTION.get_or_init(|| {
        let header = vec![
            Param {
                name: "pubkey".to_string(),
                kind: ParamType::PublicKey,
            },
            Param {
                name: "time".to_string(),
                kind: ParamType::Time,
            },
            Param {
                name: "expire".to_string(),
                kind: ParamType::Expire,
            },
        ];
        let mut builder = FunctionBuilder::new("transfer");
        builder = builder
            .abi_version(ton_abi::contract::ABI_VERSION_2_2)
            .headers(header)
            .inputs(TransferFunctionInput::param_type());
        builder.build()
    })
}

pub fn get_details() -> &'static ton_abi::Function {
    static FUNCTION: OnceCell<ton_abi::Function> = OnceCell::new();
    FUNCTION.get_or_init(|| {
        let header = vec![
            Param {
                name: "pubkey".to_string(),
                kind: ParamType::PublicKey,
            },
            Param {
                name: "time".to_string(),
                kind: ParamType::Time,
            },
            Param {
                name: "expire".to_string(),
                kind: ParamType::Expire,
            },
        ];
        let mut builder = FunctionBuilder::new("getDetails");
        builder = builder
            .abi_version(ton_abi::contract::ABI_VERSION_2_2)
            .headers(header)
            .outputs(GetDetailsFunctionOutput::param_type());
        builder.build()
    })
}

pub fn refund() -> &'static ton_abi::Function {
    static FUNCTION: OnceCell<ton_abi::Function> = OnceCell::new();
    FUNCTION.get_or_init(|| {
        let header = vec![
            Param {
                name: "pubkey".to_string(),
                kind: ParamType::PublicKey,
            },
            Param {
                name: "time".to_string(),
                kind: ParamType::Time,
            },
            Param {
                name: "expire".to_string(),
                kind: ParamType::Expire,
            },
        ];
        let builder = FunctionBuilder::new("refund");
        builder
            .abi_version(ton_abi::contract::ABI_VERSION_2_2)
            .headers(header)
            .build()
    })
}

pub fn route() -> &'static ton_abi::Function {
    static FUNCTION: OnceCell<ton_abi::Function> = OnceCell::new();
    FUNCTION.get_or_init(|| {
        let header = vec![
            Param {
                name: "pubkey".to_string(),
                kind: ParamType::PublicKey,
            },
            Param {
                name: "time".to_string(),
                kind: ParamType::Time,
            },
            Param {
                name: "expire".to_string(),
                kind: ParamType::Expire,
            },
        ];
        let mut builder = FunctionBuilder::new("route");
        builder = builder
            .abi_version(ton_abi::contract::ABI_VERSION_2_2)
            .headers(header)
            .inputs(RouteFunctionInput::param_type());
        builder.build()
    })
}

pub fn htlc_reset() -> &'static ton_abi::Event {
    static EVENT: OnceCell<ton_abi::Event> = OnceCell::new();
    EVENT.get_or_init(|| {
        let builder = EventBuilder::new("reset");
        builder
            .abi_version(ton_abi::contract::ABI_VERSION_2_2)
            .build()
    })
}

pub fn htlc_new() -> &'static ton_abi::Event {
    static EVENT: OnceCell<ton_abi::Event> = OnceCell::new();
    EVENT.get_or_init(|| {
        let mut builder = EventBuilder::new("HTLCNew");
        builder = builder
            .abi_version(ton_abi::contract::ABI_VERSION_2_2)
            .inputs(HTLCNewEventInput::param_type());
        builder.build()
    })
}

pub fn htlc_refund() -> &'static ton_abi::Event {
    static EVENT: OnceCell<ton_abi::Event> = OnceCell::new();
    EVENT.get_or_init(|| {
        let mut builder = EventBuilder::new("HTLCRefund");
        builder = builder
            .abi_version(ton_abi::contract::ABI_VERSION_2_2)
            .inputs(HTLCRefundEventInput::param_type());
        builder.build()
    })
}

pub fn htlc_settle() -> &'static ton_abi::Event {
    static EVENT: OnceCell<ton_abi::Event> = OnceCell::new();
    EVENT.get_or_init(|| {
        let mut builder = EventBuilder::new("HTLCSettle");
        builder = builder
            .abi_version(ton_abi::contract::ABI_VERSION_2_2)
            .inputs(HTLCSettleEventInput::param_type());
        builder.build()
    })
}
