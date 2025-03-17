use bincode::{config::{Configuration, standard}, serde::{encode_to_vec, decode_from_slice}};
use serde::{Serialize, Deserialize};
use anyhow::Result;
use std::{fs::File, io::{Write, Read}};
use crate::encryption::{encrypt, decrypt};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TaskFile {
    pub tasks: Vec<i128>,
}

pub fn write_taskfile(taskfile: TaskFile, filepath: &str) -> Result<()> {
    let mut file: File = File::create(filepath)?;

    let config: Configuration = standard();
    let encoded: Vec<u8> = encode_to_vec(taskfile, config)?;

    let encrypted: Vec<u8> = encrypt(encoded)?;

    file.write_all(&encrypted)?;
    file.flush()?;

    Ok(())
}

pub fn read_taskfile(filepath: &str) -> Result<TaskFile> {
    let mut file: File = File::open(filepath)?;

    let mut raw_data: Vec<_> = Vec::new();
    file.read_to_end(&mut raw_data)?;

    let decrypted: Vec<u8> = decrypt(raw_data)?;

    let config: Configuration = standard();
    let decoded: TaskFile = decode_from_slice(&decrypted, config)?.0;

    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_read() -> Result<()> {
        let write_data: TaskFile = TaskFile { tasks: vec![123] };
        let filepath: &str = "write_read.rask";

        write_taskfile(write_data.clone(), filepath)?;

        let read_taskfile: TaskFile = read_taskfile(filepath)?;
        std::fs::remove_file(filepath)?;

        assert_eq!(write_data, read_taskfile, "should be the same");
        Ok(())
    }

    #[test]
    fn empty_tasklist() -> Result<()> {
        let taskfile: TaskFile = TaskFile { tasks: vec![] };
        let filepath: &str = "empty_tasklist.rask";

        write_taskfile(taskfile.clone(), filepath)?;
        let read_taskfile: TaskFile = read_taskfile(filepath)?;

        assert_eq!(taskfile, read_taskfile, "should be the same");
        std::fs::remove_file(filepath)?;
        Ok(())
    }

    #[test]
    fn read_nonexistent_file() -> Result<()> {
        let filepath: &str = "non_existent.rask";
        let result: Result<TaskFile, anyhow::Error> = read_taskfile(filepath);

        assert!(result.is_err(), "reading a non-existent file should yield an error");
        Ok(())
    }

    #[test]
    fn read_corrupted_file() -> Result<()> {
        let filepath: &str = "corrupted.rask";
        std::fs::write(filepath, b"not encrypted or valid data")?;

        let result: Result<TaskFile, anyhow::Error> = read_taskfile(filepath);

        assert!(result.is_err(), "should fail to decrypt and decode");
        std::fs::remove_file(filepath)?;
        Ok(())
    }

    #[test]
    fn large_taskfile() -> Result<()> {
        let taskfile: TaskFile = TaskFile { tasks: (0..10_000).collect() };
        let filepath: &str = "large_taskfile.rask";

        write_taskfile(taskfile.clone(), filepath)?;
        let read_taskfile: TaskFile = read_taskfile(filepath)?;

        assert_eq!(taskfile, read_taskfile, "should be the same");
        std::fs::remove_file(filepath)?;
        Ok(())
    }
}