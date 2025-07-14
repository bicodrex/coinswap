//! The Coinswap Wallet (unsecured). Used by both the Taker and Maker.

mod api;
mod error;
mod fidelity;
mod funding;
mod rpc;
mod spend;
mod split_utxos;
mod storage;
mod swapcoin;

pub(crate) use api::{Balances, UTXOSpendInfo};
pub use error::WalletError;
pub(crate) use fidelity::{fidelity_redeemscript, FidelityBond, FidelityError};
pub use rpc::RPCConfig;
pub use spend::Destination;
pub(crate) use swapcoin::{
    IncomingSwapCoin, OutgoingSwapCoin, SwapCoin, WalletSwapCoin, WatchOnlySwapCoin,
};
pub use api::WalletBackup;
pub use api::Wallet;
pub use api::KeyMaterial;