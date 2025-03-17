use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce, Key
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

    let mut nonce: [u8; 24] = [0u8; 24];
    rng.fill_bytes(&mut nonce);

    let password: String = keychain::read("password", "rask")?;

    let mut key: [u8; 32] = derivekey::derive_key(password.clone(), salt)?;

    let cipher: XChaCha20Poly1305 = XChaCha20Poly1305::new(Key::from_slice(&key));
    let mut ciphertext: Vec<u8> = cipher.encrypt(XNonce::from_slice(&nonce), Payload { msg: &plaintext, aad: &[] })
        .map_err(|e| anyhow::anyhow!(e))
        .context("error during encryption")?;

    let mut combined: Vec<u8> = salt.to_vec();
    combined.extend_from_slice(&nonce);
    combined.extend_from_slice(&ciphertext);

    key.zeroize();
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
        let encrypted: Result<Vec<u8>, anyhow::Error> = encrypt(b"Super secret message".to_vec());

        assert!(!encrypted.is_err(), "shouldn't be an error");
        Ok(())
    }
}