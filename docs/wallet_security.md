# Backup the wallet
## Without Backup Encryption
```
RUST_BACKTRACE=1 cargo run --bin taker -- -a user:password -r 127.0.0.1:18443 -v trace -w taker-wallet wallet-backup
```
## With Backup Encryption
```
RUST_BACKTRACE=1 cargo run --bin taker -- -a user:password -r 127.0.0.1:18443 -v trace -w taker-wallet wallet-backup --encrypt
```
# Restore the wallet
The wallet restore, can restore the wallet, both as encrypter or plain wallet. To specify if the restored wallet need to be encrypted, you should just follow the interactive prompt
```
RUST_BACKTRACE=1 cargo run --bin taker -- -a user:password -r 127.0.0.1:18443 -v trace -w taker-wallet wallet-restore --backup-file taker-wallet-backup.json
```