use keyring::Entry;
use anyhow::Result;

pub fn read(service: &str, user: &str) -> Result<Vec<u8>> {
    let entry: Entry = Entry::new(service, user)?;
    let secret: Vec<u8> = entry.get_secret()?;
    Ok(secret)
}

pub fn write(service: &str, user: &str, mut secret: Vec<u8>) -> Result<()> {
    let entry: Entry = Entry::new(service, user)?;
    entry.set_secret(&secret)?;
    secret.fill(0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
}