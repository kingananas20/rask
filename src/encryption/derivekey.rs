use zeroize::Zeroize;
use argon2::Argon2;
use anyhow::{Context, Result};

pub fn derive_key(mut password: String, salt: [u8; 16]) -> Result<[u8; 32]> {
    let mut key: [u8; 32] = [0u8; 32];
    Argon2::default().hash_password_into(password.as_bytes(), &salt, &mut key)
        .map_err(|e| anyhow::anyhow!(e))
        .context("error during key derivation")?;
    password.zeroize();
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

        let key: [u8; 32] = derive_key("SuperSecretPassword".to_string(), salt)?;
        println!("{:?}\n{:?}", key, salt);
        assert!(true);
        Ok(())
    }   
}