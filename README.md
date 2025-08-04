# Bitceilium Project for Unite DeFi Hackathon

## Description

We leverage the Bitcoin Lightning Network as a global decentralized *escrow address*, ensuring the BTC leg of the swap functions reliably while preserving 1inch’s role as an auction platform for Lightning liquidity providers.

In addition, we discovered that our platform can bring other chains to 1inch, and we are actively exploring that direction. Alongside LN BTC and on-chain BTC, we are enabling integration of TVM-based networks via a Lightning node. Basic HTLC contracts can be adapted in the future for a more "1inch-style" asset swap experience.

On the UX/UI side, we are experimenting with QR-code-driven remote signers for 1inch swap contracts. This will enable users to access 1inch from mobile Lightning wallets. According to River Financial’s estimates, as of September 2023, there were between 279,000 and 1.116 million monthly active Lightning users (with a ratio of 1:8 non-custodial to custodial users). There were between 1.8 and 3.7 million Lightning wallets in total, with at least 122 million wallets downloaded that support Lightning. We rely on technology that is available in nearly every Lightning wallet on the market. The expected use case for these wallets is interacting with stablecoins in one way or another while using 1inch.

Key components:

1. 1inch LNURL authenticator https://github.com/SatsBridge/1inch-lightning-swap/blob/main/lnurl2evm/src/1inch-client.ts: built specifically to approve actions from Bitcoin Lightning wallets via static QR codes.
2. Miniscript-based Taproot Bitcoin wallet https://github.com/SatsBridge/1inch-lightning-swap/blob/main/tests/btc.ts: implements default policy for partial fills and refunds.
3. Core Lightning client library https://github.com/SatsBridge/1inch-lightning-swap/blob/main/tests/cln.js: used to communicate with a Lightning node.
4. A Solidity TVM HTLC and Core Lightning plugin for communicating for the TVM compatible networks.

## Tech Stack

The project relies on Core Lightning, maintained by Blockstream. Thanks to its flexible plugin system and stable interfaces, we were able to implement light clients for external networks and establish communication for updating HTLCs on their side. These plugins are built using Rust, with Alloy and Nekoton libraries under the hood. A planned implementation of a dedicated 1inch plugin was not successful due to the complexity of the smart contracts and issues with handling Foundry's Rust bindings.

The project also leverages a set of TypeScript libraries for Miniscript, maintained by Bitcoinerlab. These libraries turned out to be critical in building the Bitcoin Escrow Wallet used for 1inch <> BTC cross-chain swaps.

To integrate LNURL with 1inch, we relied on Account Abstraction libraries by Pimlico. Special thanks to Sergei Pothekhin for his consultations, which helped us move faster.


## Installation

Install example deps

```shell
npm install --save-dev pnpm --legacy-peer-deps
pnpm install
```

Install [foundry](https://book.getfoundry.sh/getting-started/installation)

```shell
curl -L https://foundry.paradigm.xyz | bash
```

Install contract deps

```shell
forge install
```

```shell
anvil --host 0.0.0.0 --port 8545 --accounts 20 --balance 10000 & 
```


## Running

To run tests you need to provide fork urls for Ethereum and Bsc

```shell
SRC_CHAIN_RPC=ETH_FORK_URL DST_CHAIN_RPC=BNB_FORK_URL pnpm test
```

### Public rpc

| Chain    | Url                          |
|----------|------------------------------|
| Ethereum | https://eth.merkle.io        |
| BSC      | wss://bsc-rpc.publicnode.com |

## Test accounts

### Available Accounts

```
(0) 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" Owner of EscrowFactory
(1) 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d: "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" User
(2) 0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a: "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC" Resolver
```
