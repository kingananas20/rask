use bincode::{config::{standard, Configuration}, serde::encode_to_vec};
use anyhow::{Context, Result};
use serde::Serialize;
use std::{fs::File, io::Write};
use crate::encryption::encrypt;

pub fn write<T: Serialize>(filepath: &str, data: T) -> Result<()> {
    let mut file: File = File::create(filepath)
        .with_context(|| format!("failed to create file at {}", filepath))?;

    let config: Configuration = standard();
    let encoded: Vec<u8> = encode_to_vec(data, config)
        .context("failed during binary encoding")?;

    let encrypted: Vec<u8> = encrypt(encoded)
        .context("failed during encryption")?;

    file.write_all(&encrypted)
        .context("failed during writing")?;
    file.flush()
        .context("failed during flushing")?;

    Ok(())
}