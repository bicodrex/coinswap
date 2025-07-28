//! The Coinswap Wallet (unsecured). Used by both the Taker and Maker.

mod api;
mod error;
mod fidelity;
mod funding;
mod rpc;
mod security;
mod spend;
mod split_utxos;
mod storage;
mod swapcoin;

pub use api::Balances;
pub(crate) use api::UTXOSpendInfo;
pub use api::{Wallet, WalletBackup};
pub use error::WalletError;
pub(crate) use fidelity::{fidelity_redeemscript, FidelityBond, FidelityError};
pub use rpc::RPCConfig;
pub use security::{KeyMaterial, SerdeCbor, SerdeJson};
pub use spend::Destination;
pub(crate) use swapcoin::{
    IncomingSwapCoin, OutgoingSwapCoin, SwapCoin, WalletSwapCoin, WatchOnlySwapCoin,
};
