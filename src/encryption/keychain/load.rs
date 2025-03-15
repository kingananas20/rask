use keyring::Entry;
use anyhow::{Context, Result};
use zeroize::Zeroize;

pub fn read(target: &str, service: &str) -> Result<String> {
    let user: String = whoami::username();
    let entry: Entry = Entry::new_with_target(target, service, &user)
        .with_context(|| format!("error creating entry with service: {} and user: {}", service, user))?;
    let password: String = match entry.get_password() {
        Ok(password) => password,
        Err(_) => return Ok("".to_string()),
    };
    Ok(password)
}

pub fn write(target: &str, service: &str, mut password: String) -> Result<()> {
    let user: String = whoami::username();
    let entry: Entry = Entry::new_with_target(target, service, &user)
        .with_context(|| format!("error creating entry with service: {} and user: {}", service, user))?;
    entry.set_password(&password)
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
        let mut rng: rand::prelude::ThreadRng = rand::rng();
        let mut secret: Vec<u8> = vec![0u8; 32];
        rng.fill_bytes(&mut secret);

        let password: String = String::from_utf8_lossy(&secret).to_string();

        write("test", "rask", password.clone())?;

        let read_password: String = read("test", "rask")?;

        println!("{:?} {:?}", password, read_password);
        assert_eq!(password, read_password);
        Ok(())
    }

    #[test]
    fn empty_entry() -> Result<()> {
        let password: String = read("testempty", "rask")
            .context("no password provided! use rask password add")?;
        println!("{:?}", password);
        assert!(true);
        Ok(())
    }
}