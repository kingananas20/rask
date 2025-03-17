use bincode::{config::{standard, Configuration}, serde::encode_to_vec};
use anyhow::Result;
use serde::Serialize;
use std::{fs::File, io::Write};
use crate::encryption::encrypt;

pub fn write<T: Serialize>(filepath: &str, data: T) -> Result<()> {
    let mut file: File = File::create(filepath)?;

    let config: Configuration = standard();
    let encoded: Vec<u8> = encode_to_vec(data, config)?;

    let encrypted: Vec<u8> = encrypt(encoded)?;

    file.write_all(&encrypted)?;
    file.flush()?;

    Ok(())
}