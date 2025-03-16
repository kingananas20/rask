use aes_gcm::{
    aead::{Aead, KeyInit, Payload}, Aes256Gcm, Key // Or `Aes128Gcm`
};
use anyhow::{Context, Result};
use rand::RngCore;
use super::keychain;
use super::derivekey;
use zeroize::Zeroize;

pub fn encrypt(plaintext: Vec<u8>) -> Result<Vec<u8>> {
    let mut rng: rand::prelude::ThreadRng = rand::rng();
    let mut salt: [u8; 16] = [0u8; 16];
    rng.fill_bytes(&mut salt);

    let mut nonce: [u8; 12] = [0u8; 12];
    rng.fill_bytes(&mut nonce);

    let password: String = keychain::read("password", "rask")?;

    let key: [u8; 32] = derivekey::derive_key(password, salt);
    let key: &sha2::digest::generic_array::GenericArray<u8, _> = Key::<Aes256Gcm>::from_slice(&key);

    let cipher: Aes256Gcm = Aes256Gcm::new(key);
    let mut ciphertext: Vec<u8> = cipher.encrypt(&nonce.into(), Payload { msg: &plaintext, aad: &[] })
        .map_err(|e| anyhow::anyhow!(e))
        .context("error during encryption")?;

    let mut combined: Vec<u8> = salt.to_vec();
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&ciphertext);

    nonce.zeroize();
    salt.zeroize();
    ciphertext.zeroize();

    Ok(combined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    #[test]
    fn encrypt_test() -> Result<()> {
        let encrypted: Vec<u8> = encrypt(b"Super Secret message".to_vec())?;

        println!("{:?}", encrypted);

        assert!(true);
        Ok(())
    }
}