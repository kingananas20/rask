use anyhow::{Context, Result};
use keyring::Entry;
use zeroize::Zeroize;

pub fn read(target: &str, service: &str) -> Result<String> {
    let user = whoami::username();
    let entry = Entry::new_with_target(target, service, &user).with_context(|| {
        format!(
            "error creating entry with\nservice: {}\nuser: {}\ntarget: {}",
            service, user, target
        )
    })?;
    let password = match entry.get_password() {
        Ok(password) => password,
        Err(keyring::Error::NoEntry) => return Ok("".to_string()),
        Err(e) => return Err(anyhow::anyhow!("failed to retrieve password: {}", e)),
    };
    Ok(password)
}

pub fn write(target: &str, service: &str, mut password: String) -> Result<()> {
    let user = whoami::username();
    let entry = Entry::new_with_target(target, service, &user).with_context(|| {
        format!(
            "error creating entry with\nservice: {}\nuser: {}\ntarget: {}",
            service, user, target
        )
    })?;
    entry
        .set_password(&password)
        .context("error storing password")?;
    password.zeroize();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{self, RngCore};

    #[test]
    fn keychain() -> Result<()> {
        let mut rng = rand::rng();
        let mut secret = vec![0u8; 32];
        rng.fill_bytes(&mut secret);

        let password = String::from_utf8_lossy(&secret).to_string();

        write("test", "rask", password.clone())?;

        let read_password = read("test", "rask")?;

        assert_eq!(password, read_password, "should be the same");
        Ok(())
    }

    #[test]
    fn empty_entry() -> Result<()> {
        let password = read("testempty", "rask")?;
        assert_eq!(password, "".to_string(), "should be an empty string");
        Ok(())
    }

    #[test]
    fn overwrite_password() -> Result<()> {
        let mut rng = rand::rng();
        let mut secret1 = vec![0u8; 32];
        let mut secret2 = vec![0u8; 32];
        rng.fill_bytes(&mut secret1);
        rng.fill_bytes(&mut secret2);

        let passwd1 = String::from_utf8_lossy(&secret1).to_string();
        let passwd2 = String::from_utf8_lossy(&secret2).to_string();

        write("testoverwrite", "rask", passwd1.clone())?;
        write("testoverwrite", "rask", passwd2.clone())?;

        let password = read("testoverwrite", "rask")?;
        assert_ne!(password, passwd1, "shouldn't be the same");
        assert_eq!(password, passwd2, "should be the same");

        Ok(())
    }
}
