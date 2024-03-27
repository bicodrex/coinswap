#![cfg(feature = "integration-test")]
use bitcoin::Amount;
use coinswap::{
    maker::{start_maker_server, MakerBehavior},
    market::directory::{start_directory_server, DirectoryServer},
    taker::SwapParams,
};

mod test_framework;
use test_framework::*;

use log::{info, warn};
use std::{assert_eq, sync::Arc, thread, time::Duration};

/// This test demonstrates a standard coinswap round between a Taker and 2 Makers. Nothing goes wrong
/// and the coinswap completes successfully.
#[tokio::test]
async fn test_standard_coinswap() {
    // ---- Setup ----

    // 2 Makers with Normal behavior.
    let makers_config_map = [
        ((6102, 19051), MakerBehavior::Normal),
        ((16102, 19052), MakerBehavior::Normal),
    ];

    // Initiate test framework, Makers and a Taker with default behavior.
    let (test_framework, taker, makers) =
        TestFramework::init(None, makers_config_map.into(), None).await;

    warn!("Running Test: Standard Coinswap Procedure");

    info!("Initiating Directory Server .....");

    let directory_server_instance = Arc::new(DirectoryServer::new(None).unwrap());
    let directory_server_instance_clone = directory_server_instance.clone();
    thread::spawn(move || {
        start_directory_server(directory_server_instance_clone);
    });

    info!("Initiating Takers...");
    // Fund the Taker and Makers with 3 utxos of 0.05 btc each.
    for _ in 0..3 {
        let taker_address = taker
            .write()
            .unwrap()
            .get_wallet_mut()
            .get_next_external_address()
            .unwrap();
        test_framework.send_to_address(&taker_address, Amount::from_btc(0.05).unwrap());
        makers.iter().for_each(|maker| {
            let maker_addrs = maker
                .get_wallet()
                .write()
                .unwrap()
                .get_next_external_address()
                .unwrap();
            test_framework.send_to_address(&maker_addrs, Amount::from_btc(0.05).unwrap());
        });
    }

    // Coins for fidelity creation
    makers.iter().for_each(|maker| {
        let maker_addrs = maker
            .get_wallet()
            .write()
            .unwrap()
            .get_next_external_address()
            .unwrap();
        test_framework.send_to_address(&maker_addrs, Amount::from_btc(0.05).unwrap());
    });

    // confirm balances
    test_framework.generate_1_block();

    // --- Basic Checks ----

    // Assert external address index reached to 4.
    assert_eq!(taker.read().unwrap().get_wallet().get_external_index(), &3);
    makers.iter().for_each(|maker| {
        let next_external_index = *maker.get_wallet().read().unwrap().get_external_index();
        assert_eq!(next_external_index, 4);
    });

    // Check if utxo list looks good.
    // TODO: Assert other interesting things from the utxo list.

    let mut all_utxos = taker.read().unwrap().get_wallet().get_all_utxo().unwrap();

    let taker_no_of_descriptor_utxo_unspent = taker
        .read()
        .unwrap()
        .get_wallet()
        .list_descriptor_utxo_spend_info(Some(&all_utxos))
        .unwrap()
        .len();

    let taker_no_of_fidelity_unspent = taker
        .read()
        .unwrap()
        .get_wallet()
        .list_fidelity_spend_info(Some(&all_utxos))
        .unwrap()
        .len();
    let taker_no_of_swap_coin_unspent = taker
        .read()
        .unwrap()
        .get_wallet()
        .list_swap_coin_utxo_spend_info(Some(&all_utxos))
        .unwrap()
        .len();

    let taker_no_of_live_contract_unspent = taker
        .read()
        .unwrap()
        .get_wallet()
        .list_live_contract_spend_info(Some(&all_utxos))
        .unwrap()
        .len();

    assert_eq!(taker_no_of_descriptor_utxo_unspent, 3);
    assert_eq!(taker_no_of_fidelity_unspent, 0);
    assert_eq!(taker_no_of_swap_coin_unspent, 0);
    assert_eq!(taker_no_of_live_contract_unspent, 0);

    makers.iter().for_each(|maker| {
        all_utxos = maker.get_wallet().read().unwrap().get_all_utxo().unwrap();

        let maker_no_of_descriptor_utxo_unspent = maker
            .get_wallet()
            .read()
            .unwrap()
            .list_descriptor_utxo_spend_info(Some(&all_utxos))
            .unwrap()
            .len();

        let maker_no_of_fidelity_unspent = maker
            .get_wallet()
            .read()
            .unwrap()
            .list_fidelity_spend_info(Some(&all_utxos))
            .unwrap()
            .len();

        let maker_no_of_swap_coin_unspent = maker
            .get_wallet()
            .read()
            .unwrap()
            .list_swap_coin_utxo_spend_info(Some(&all_utxos))
            .unwrap()
            .len();

        let maker_no_of_live_contract_unspent = maker
            .get_wallet()
            .read()
            .unwrap()
            .list_live_contract_spend_info(Some(&all_utxos))
            .unwrap()
            .len();

        assert_eq!(maker_no_of_descriptor_utxo_unspent, 4);
        assert_eq!(maker_no_of_fidelity_unspent, 0);
        assert_eq!(maker_no_of_swap_coin_unspent, 0);
        assert_eq!(maker_no_of_live_contract_unspent, 0);
    });

    // Check locking non-wallet utxos worked.
    taker
        .read()
        .unwrap()
        .get_wallet()
        .lock_unspendable_utxos()
        .unwrap();
    makers.iter().for_each(|maker| {
        maker
            .get_wallet()
            .read()
            .unwrap()
            .lock_unspendable_utxos()
            .unwrap();
    });

    // ---- Start Servers and attempt Swap ----

    info!("Initiating Maker...");
    // Start the Maker server threads
    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker_clone = maker.clone();
            thread::spawn(move || {
                start_maker_server(maker_clone).unwrap();
            })
        })
        .collect::<Vec<_>>();

    // Start swap
    thread::sleep(Duration::from_secs(360)); // Take a delay because Makers take time to fully setup.
    let swap_params = SwapParams {
        send_amount: 500000,
        maker_count: 2,
        tx_count: 3,
        required_confirms: 1,
        fee_rate: 1000,
    };

    info!("Initiating coinswap protocol");
    // Spawn a Taker coinswap thread.
    let taker_clone = taker.clone();
    let taker_thread = thread::spawn(move || {
        taker_clone
            .write()
            .unwrap()
            .do_coinswap(swap_params)
            .unwrap();
    });

    // Wait for Taker swap thread to conclude.
    taker_thread.join().unwrap();

    // Wait for Maker threads to conclude.
    makers.iter().for_each(|maker| maker.shutdown().unwrap());
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    info!("All coinswaps processed successfully. Transaction complete.");

    let _ = directory_server_instance.shutdown();

    thread::sleep(Duration::from_secs(10));

    // ---- After Swap Asserts ----

    warn!("Final Balance Checks for process");
    // Check everybody hash 6 swapcoins.
    assert_eq!(taker.read().unwrap().get_wallet().get_swapcoins_count(), 6);
    makers.iter().for_each(|maker| {
        let swapcoin_count = maker.get_wallet().read().unwrap().get_swapcoins_count();
        assert_eq!(swapcoin_count, 6);
    });

    // Check balances makes sense
    all_utxos = taker.read().unwrap().get_wallet().get_all_utxo().unwrap();
    warn!(
        "Taker balance : {}",
        taker
            .read()
            .unwrap()
            .get_wallet()
            .balance_descriptor_utxo(Some(&all_utxos))
            .unwrap()
            + taker
                .read()
                .unwrap()
                .get_wallet()
                .balance_swap_coins(Some(&all_utxos))
                .unwrap()
    );
    let taker_balance_fidelity = taker
        .read()
        .unwrap()
        .get_wallet()
        .balance_fidelity_bonds(Some(&all_utxos))
        .unwrap();
    let taker_balance_descriptor_utxo = taker
        .read()
        .unwrap()
        .get_wallet()
        .balance_descriptor_utxo(Some(&all_utxos))
        .unwrap();
    let taker_balance_swap_coins = taker
        .read()
        .unwrap()
        .get_wallet()
        .balance_swap_coins(Some(&all_utxos))
        .unwrap();
    let taker_balance_live_contract = taker
        .read()
        .unwrap()
        .get_wallet()
        .balance_live_contract(Some(&all_utxos))
        .unwrap();
    assert!(
        taker_balance_fidelity
            + taker_balance_descriptor_utxo
            + taker_balance_swap_coins
            + taker_balance_live_contract
            < Amount::from_btc(0.15).unwrap()
    );
    assert_eq!(
        taker_balance_descriptor_utxo,
        Amount::from_btc(0.14499541).unwrap()
    );
    assert_eq!(
        taker_balance_swap_coins,
        Amount::from_btc(0.0048584).unwrap()
    );
    assert_eq!(taker_balance_fidelity, Amount::from_btc(0.0).unwrap());
    assert_eq!(taker_balance_live_contract, Amount::from_btc(0.0).unwrap());

    makers.iter().for_each(|maker| {
        all_utxos = maker.get_wallet().read().unwrap().get_all_utxo().unwrap();
        let maker_balance_fidelity = maker
            .get_wallet()
            .read()
            .unwrap()
            .balance_fidelity_bonds(Some(&all_utxos))
            .unwrap();
        let maker_balance_descriptor_utxo = maker
            .get_wallet()
            .read()
            .unwrap()
            .balance_descriptor_utxo(Some(&all_utxos))
            .unwrap();
        let maker_balance_swap_coins = maker
            .get_wallet()
            .read()
            .unwrap()
            .balance_swap_coins(Some(&all_utxos))
            .unwrap();
        let maker_balance_live_contract = maker
            .get_wallet()
            .read()
            .unwrap()
            .balance_live_contract(Some(&all_utxos))
            .unwrap();

        assert!(
            maker_balance_descriptor_utxo == Amount::from_btc(0.14505657).unwrap()
                || maker_balance_descriptor_utxo == Amount::from_btc(0.14512701).unwrap(),
            "maker_balance_descriptor_utxo does not match any of the expected values"
        );
        assert!(
            maker_balance_swap_coins == Amount::from_btc(0.00492884).unwrap()
                || maker_balance_swap_coins == Amount::from_btc(0.005).unwrap(),
            "maker_balance_swap_coins does not match any of the expected values"
        );
        assert_eq!(maker_balance_fidelity, Amount::from_btc(0.0).unwrap());
        assert_eq!(maker_balance_live_contract, Amount::from_btc(0.0).unwrap());

        let balance = maker_balance_descriptor_utxo + maker_balance_swap_coins;

        assert!(balance > Amount::from_btc(0.15).unwrap());
    });

    info!("All checks successful. Terminating integration test case");

    // Stop test and clean everything.
    // comment this line if you want the wallet directory and bitcoind to live. Can be useful for
    // after test debugging.
    test_framework.stop();
}
