use aes_gcm::{aead::{Aead, OsRng}, AeadCore, Aes256Gcm, Key, KeyInit};
use pbkdf2::pbkdf2_hmac_array;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::Sha256;

use crate::{utill};
use std::error::Error;

/// Salt used for key derivation from a user-provided passphrase.
const PBKDF2_SALT: &[u8; 8] = b"coinswap";
/// Number of PBKDF2 iterations to strengthen passphrase-derived keys.
///
/// In production, this is set to **600,000 iterations**, following
/// modern password security guidance from the
/// [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
///
/// During testing or integration tests, the iteration count is reduced to 1
/// for performance.
const PBKDF2_ITERATIONS: u32 = if cfg!(feature = "integration-test") || cfg!(test) {
    1
} else {
    600_000
};

/// Holds derived cryptographic key material used for encrypting and decrypting wallet data.
#[derive(Debug, Clone)]
pub struct KeyMaterial {
    /// A 256-bit key derived from the user’s passphrase via PBKDF2.
    /// This key is used with AES-GCM for encryption/decryption.
    pub key: [u8; 32],
    /// Nonce used for AES-GCM encryption, generated when a new wallet is created.
    /// When loading an existing wallet, this is initially `None`.
    /// It is populated after reading the stored nonce from disk.
    pub nonce: Option<Vec<u8>>,
    
}
impl KeyMaterial {
    /// New from password
    pub fn new_from_password(password: String) -> Self {
        KeyMaterial {
            key: pbkdf2_hmac_array::<Sha256, 32>(
                password.as_bytes(),
                PBKDF2_SALT,
                PBKDF2_ITERATIONS,
            ),
            nonce: Some(Aes256Gcm::generate_nonce(&mut OsRng).as_slice().to_vec()),
        }
    }
    /// Existing from password
    pub fn existing_from_password(password: String) -> Self {
        KeyMaterial {
            key: pbkdf2_hmac_array::<Sha256, 32>(
                password.as_bytes(),
                PBKDF2_SALT,
                PBKDF2_ITERATIONS,
            ),
            nonce: None,
        }
    }
}

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
