use zeroize::Zeroize;
use argon2::Argon2;
use anyhow::{Context, Result};

pub fn derive_key(mut password: String, mut salt: [u8; 16]) -> Result<[u8; 32]> {
    let mut key: [u8; 32] = [0u8; 32];
    Argon2::default().hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| anyhow::anyhow!(e))
        .context("error during key derivation")?;
    password.zeroize();
    salt.zeroize();
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn derive() -> Result<()> {
        let mut rng: rand::prelude::ThreadRng = rand::rng();
        let mut salt: [u8; 16] = [0u8; 16];
        rng.fill_bytes(&mut salt);

        let key1: [u8; 32] = derive_key("SuperSecretPassword".to_string(), salt)?;
        let key2: [u8; 32] = derive_key("SuperSecretPassword".to_string(), salt)?;
        assert_eq!(key1, key2);
        Ok(())
    }   

    #[test]
    fn derive_different_keys() -> Result<()> {
        let mut rng: rand::prelude::ThreadRng = rand::rng();
        let mut salt: [u8; 16] = [0u8; 16];
        rng.fill_bytes(&mut salt);

        let key1: [u8; 32] = derive_key("SuperSecretPassword1".to_string(), salt)?;
        let key2: [u8; 32] = derive_key("SuperSecretPassword2".to_string(), salt)?;
        assert_ne!(key1, key2);
        Ok(())
    }
}