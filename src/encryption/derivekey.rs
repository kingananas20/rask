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
    fn derive_same_keys() -> Result<()> {
        let mut rng: rand::prelude::ThreadRng = rand::rng();
        let mut salt: [u8; 16] = [0u8; 16];
        rng.fill_bytes(&mut salt);

        let key1: [u8; 32] = derive_key("SuperSecretPassword".to_string(), salt)?;
        let key2: [u8; 32] = derive_key("SuperSecretPassword".to_string(), salt)?;
        assert_eq!(key1, key2, "should be the same");
        Ok(())
    }

    #[test]
    fn derive_different_keys() -> Result<()> {
        let mut rng: rand::prelude::ThreadRng = rand::rng();
        let mut salt1: [u8; 16] = [0u8; 16];
        let mut salt2: [u8; 16] = [0u8; 16];
        rng.fill_bytes(&mut salt1);
        rng.fill_bytes(&mut salt2);

        let password1: String = "SuperSecretPassword1".to_string();
        let password2: String = "SuperSecretPassword2".to_string();

        // Different passwords, same salts
        let key1: [u8; 32] = derive_key(password1.clone(), salt1)?;
        let key2: [u8; 32] = derive_key(password2.clone(), salt1)?;
        assert_ne!(key1, key2, "shouldn't be the same");

        // Same passwords, different salts
        let key3: [u8; 32] = derive_key(password1.clone(), salt1)?;
        let key4: [u8; 32] = derive_key(password1.clone(), salt2)?;
        assert_ne!(key3, key4, "shouldn't be the same");

        // Different passwords, different salts
        let key5: [u8; 32] = derive_key(password1.clone(), salt1)?;
        let key6: [u8; 32] = derive_key(password2, salt2)?;
        assert_ne!(key5, key6, "shouldn't be the same");
        Ok(())
    }
}