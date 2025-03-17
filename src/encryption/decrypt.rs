use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce, Key
};
use anyhow::{Context, Result};
use super::keychain;
use super::derivekey;
use zeroize::Zeroize;

pub fn decrypt(encrypted: Vec<u8>) -> Result<Vec<u8>> {
    let salt: [u8; 16] = encrypted[0..16].try_into().context("failed to extract salt")?;
    let nonce: [u8; 24] = encrypted[16..40].try_into().context("failed to extract nonce")?;
    let ciphertext: Vec<u8> = encrypted[40..].to_vec();
    let password: String = keychain::read("password", "rask")?;

    let mut key: [u8; 32] = derivekey::derive_key(password, salt)?;

    let cipher: XChaCha20Poly1305 = XChaCha20Poly1305::new(Key::from_slice(&key));
    let plaintext: Vec<u8> = cipher.decrypt(XNonce::from_slice(&nonce), Payload { msg: &ciphertext, aad: &[] })
        .map_err(|e| anyhow::anyhow!(e))
        .context("error during decryption")?;

    key.zeroize();
    
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use crate::encryption::encrypt::encrypt;
    use rand::RngCore;
    use super::*;

    #[test]
    fn encrypt_decrypt() -> Result<()> {
        let mut rng: rand::prelude::ThreadRng = rand::rng();
        let mut data: [u8; 128] = [0u8; 128];
        rng.fill_bytes(&mut data);

        let encrypted_data: Vec<u8> = encrypt(data.to_vec())?;

        let decrypted_data: Vec<u8> = decrypt(encrypted_data.clone())?;

        assert_eq!(data, * decrypted_data, "should be the same");
        Ok(())
    }

    #[test]
    fn encrypt_decrypt_various_inputs() -> Result<()> {
        let cases: [Vec<u8>; 5] = [
            vec![],
            vec![0],
            b"Hello, \xE4\xB8\x96 \xE7\x95\x8C!".to_vec(),
            vec![1, 2, 3, 4, 5, 255],
            vec![42; 1024],
        ];
        for case in cases {
            let encrypted_data: Vec<u8> = encrypt(case.clone())?;
            let decrypted_data: Vec<u8> = decrypt(encrypted_data)?;
            assert_eq!(decrypted_data, case, "should be the same");
        }

        Ok(())
    }

    #[test]
    fn changed_ciphertext() -> Result<()> {
        let mut rng: rand::prelude::ThreadRng = rand::rng();
        let mut data: [u8; 128] = [0u8; 128];
        rng.fill_bytes(&mut data);

        let mut encrypted_data: Vec<u8> = encrypt(data.to_vec())?;

        encrypted_data[100] = 0;

        let decrypted_data: Result<Vec<u8>, _> = decrypt(encrypted_data.clone());

        assert!(decrypted_data.is_err(), "the decryption should fail");

        let decrypted_data: Vec<u8> = decrypted_data.unwrap_or_default();
        assert_ne!(data, *decrypted_data, "decrypted data should not match the original");
        Ok(())
    }
}