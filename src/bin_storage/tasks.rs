use bincode::{config::{Configuration, standard}, serde::{encode_to_vec, decode_from_slice}};
use serde::{Serialize, Deserialize};
use anyhow::Result;
use std::{fs::File, io::{Write, Read}};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskFile {
    pub tasks: Vec<i128>,
}

pub fn write_taskfile(taskfile: TaskFile, filepath: &str) -> Result<()> {
    let mut file: File = File::create(filepath)?;

    let config: Configuration = standard();
    let encoded: Vec<u8> = encode_to_vec(taskfile, config)?;

    // Add AES-256 encryption later

    file.write_all(&encoded)?;
    file.flush()?;

    Ok(())
}

pub fn read_taskfile(filepath: &str) -> Result<TaskFile> {
    let mut file: File = File::open(filepath)?;

    let mut raw_data: Vec<_> = Vec::new();
    file.read_to_end(&mut raw_data)?;

    // Decrypt AES-256 encryption

    let config: Configuration = standard();
    let decoded: TaskFile = decode_from_slice(&raw_data, config)?.0;

    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_and_read() -> Result<()> {
        let write_data: TaskFile = TaskFile { tasks: vec![123] };
        write_taskfile(write_data.clone(), "./data/tasks.rask")?;

        let read_data: TaskFile = read_taskfile("./data/tasks.rask")?;

        assert_eq!(write_data, read_data);

        Ok(())
    }
}