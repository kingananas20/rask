use keyring::Entry;
use anyhow::{Context, Result};

pub fn read(service: &str, user: &str) -> Result<Vec<u8>> {
    let entry: Entry = Entry::new(service, user)
    .with_context(|| format!("error creating entry with service: {} and user: {}", service, user))?;
    let secret: Vec<u8> = entry.get_secret()
        .context("error getting secret")?;
    Ok(secret)
}

pub fn write(service: &str, user: &str, mut secret: Vec<u8>) -> Result<()> {
    let entry: Entry = Entry::new(service, user)
        .with_context(|| format!("error creating entry with service: {} and user: {}", service, user))?;
    entry.set_secret(&secret)
        .context("error setting secret")?;
    secret.fill(0);
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

        write("rask", "test", secret.clone())?;

        let read_secret: Vec<u8> = read("rask", "test")?;

        println!("{:?} {:?}", secret, read_secret);
        assert_eq!(secret, read_secret);
        Ok(())
    }
}