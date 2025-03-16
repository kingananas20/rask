use aes_gcm::{
    aead::{Aead, KeyInit, Payload}, Aes256Gcm, Key // Or `Aes128Gcm`
};
use anyhow::{Context, Result};
use super::keychain;
use super::derivekey;

pub fn decrypt(encrypted: Vec<u8>) -> Result<Vec<u8>> {
    let salt: [u8; 16] = encrypted[0..16].try_into().context("failed to extract salt")?;
    let nonce: [u8; 12] = encrypted[16..28].try_into().context("failed to extract nonce")?;
    let ciphertext: Vec<u8> = encrypted[28..].to_vec();
    let password: String = keychain::read("password", "rask")?;

    let key: [u8; 32] = derivekey::derive_key(password, salt);
    let key: &sha2::digest::generic_array::GenericArray<u8, _> = Key::<Aes256Gcm>::from_slice(&key);

    let cipher: Aes256Gcm = Aes256Gcm::new(key);
    let plaintext: Vec<u8> = cipher.decrypt(&nonce.into(), Payload { msg: &ciphertext, aad: &[] })
        .map_err(|e| anyhow::anyhow!(e))
        .context("error during decryption")?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use crate::encryption::encrypt;
    use rand::RngCore;
    use super::*;

    #[test]
    fn encrypt_and_decrypt() -> Result<()> {
        let mut rng: rand::prelude::ThreadRng = rand::rng();
        let mut data: [u8; 128] = [0u8; 128];
        rng.fill_bytes(&mut data);

        let encrypted_data: Vec<u8> = encrypt::encrypt(data.to_vec())?;

        let decrypted_data: Vec<u8> = decrypt(encrypted_data.clone())?;

        println!("{:?}\n{:?}\n{:?}", data, encrypted_data, decrypted_data);
        assert_eq!(data, * decrypted_data);
        Ok(())
    }
}