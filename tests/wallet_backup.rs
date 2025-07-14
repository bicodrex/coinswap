mod test_framework;

// We just need wallet and bitcoind
// Call just bitcoind and wallet api, by taking examples from test_framework mod.rs
// Next call show demo of wallet backup and restore, both encrypted and unencrypted
// Also I need to make a docs file `wallet_security.md`, with documentation and design doc for wallet encryption / decription and backup / restore mechanism and user guide. -> Use this as SOB blog post.

use std::fs;

use bitcoin::Amount;
use bitcoind::bitcoincore_rpc::Auth;
use log::info;

use coinswap::wallet::{RPCConfig, WalletBackup};
use test_framework::init_bitcoind;

use crate::test_framework::{generate_blocks, send_to_address};

#[test]
fn backup_wallet_and_restore_after_tx() {
    info!("Running Test: Creating Wallet file, backing it up, then recieve a payment, and restore backup");

    let temp_dir = std::env::temp_dir().join("coinswap");
    let wallets_dir = temp_dir.join("wallet-tests/");

    let original_wallet_name = "original-wallet".to_string();
    let original_wallet = wallets_dir.join(&original_wallet_name);
    let wallet_backup_file = wallets_dir.join("wallet-backup".to_string());
    let restored_wallet_name = "restored-wallet".to_string();
    let restored_wallet_file = wallets_dir.join(&restored_wallet_name);

    if temp_dir.exists() {
        fs::remove_dir_all(&temp_dir).unwrap();
    }
    //println!("temporary directory : {}", temp_dir.display());

    let mut bitcoind = init_bitcoind(&temp_dir);

    let url = bitcoind.rpc_url().split_at(7).1.to_string();
    let auth = Auth::CookieFile(bitcoind.params.cookie_file.clone());


    let rpc_config = RPCConfig {
        url,
        auth,
        wallet_name: original_wallet_name.clone(),
    };

    let mut wallet = coinswap::wallet::Wallet::init(&original_wallet, &rpc_config, None).unwrap();
    //println!("Generated wallet is: {:?}", wallet);

    wallet.backup(&wallet_backup_file, false);

    let addr = wallet.get_next_external_address().unwrap();
    //print!("New address: {addr}");
    send_to_address(&bitcoind, &addr, Amount::from_btc(0.05).unwrap());
    generate_blocks(&bitcoind, 1);

    wallet.sync().unwrap();

    let restored_wallet = WalletBackup::restore(
        &restored_wallet_file,
        &rpc_config,
        &wallet_backup_file,
        restored_wallet_name,
    );

    assert_eq!(wallet, restored_wallet); // only compares .store!
    //print!("End wallet is: {:?}", restored_wallet);
    let _ = bitcoind.stop();

    info!("🎉 Wallet Backup and Restore after tx test ran succefully!");
}