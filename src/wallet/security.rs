use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{utill, wallet::KeyMaterial};
use std::error::Error;
/// Wrapper struct for storing an encrypted wallet on disk.
///
/// The standard `WalletStore` is first serialized to CBOR, then encrypted using
/// [AES-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode).
///
/// The resulting ciphertext is stored in `encrypted_wallet_store`, and the AES-GCM
/// nonce used for encryption is stored in `nonce`.
///
/// Note: The term “IV” (Initialization Vector) used in AES-GCM — including in the linked Wikipedia page —
/// refers to the same value as the nonce. They are conceptually the same in this context.
///
/// This wrapper itself is then serialized to CBOR and written to disk.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct EncryptedData {
    /// Nonce used for AES-GCM encryption (must match during decryption).
    pub(crate) nonce: Vec<u8>,
    /// AES-GCM-encrypted CBOR-serialized `WalletStore` data.
    pub(crate) encrypted_payload: Vec<u8>,
}
//TODO better error type
pub fn encrypt_struct<T: Serialize>(
    plain_struct: T,
    enc_material: &KeyMaterial,
) -> Result<EncryptedData, Box<dyn Error>> {
    // Serialize wallet data to bytes.
    let packed_store = serde_cbor::ser::to_vec(&plain_struct)?;

    // Extract nonce and key for AES-GCM.
    let material_nonce = enc_material.nonce.as_ref().unwrap();
    let nonce = aes_gcm::Nonce::from_slice(material_nonce);
    let key = Key::<Aes256Gcm>::from_slice(&enc_material.key);

    // Create AES-GCM cipher instance.
    let cipher = Aes256Gcm::new(key);

    // Encrypt the serialized wallet bytes.
    let ciphertext = cipher.encrypt(nonce, packed_store.as_ref()).unwrap();

    // Package encrypted data with nonce for storage.
    Ok(EncryptedData {
        nonce: material_nonce.clone(),
        encrypted_payload: ciphertext,
    })
}

pub fn decrypt_struct<T: DeserializeOwned, E: From<serde_cbor::Error> + std::fmt::Debug>(
    encrypted_struct: EncryptedData,
    enc_material: &KeyMaterial,
) -> Result<T, E> {
    // Deserialize the outer EncryptedWalletStore wrapper.

    let nonce_vec = encrypted_struct.nonce.clone();

    // Reconstruct AES-GCM cipher from the provided key and stored nonce.
    let key = Key::<Aes256Gcm>::from_slice(&enc_material.key);
    let cipher = Aes256Gcm::new(key);
    let nonce = aes_gcm::Nonce::from_slice(&nonce_vec);

    // Decrypt the inner WalletStore CBOR bytes.
    let packed_wallet_store = cipher
        .decrypt(nonce, encrypted_struct.encrypted_payload.as_ref())
        .expect("Error decrypting wallet, wrong passphrase?");

    utill::deserialize_from_cbor::<T, E>(packed_wallet_store)
}
