use bincode::{config::{standard, Configuration}, serde::decode_from_slice};
use anyhow::{Context, Result};
use serde::de::Deserialize;
use std::{fs::File, io::Read};
use crate::encryption::decrypt;

pub fn read<T: for<'de> Deserialize<'de>>(filepath: &str) -> Result<T> {
    let mut file: File = File::open(filepath)
        .with_context(|| format!("failed to open file at {}", filepath))?;

    let mut raw_data: Vec<_> = Vec::new();
    file.read_to_end(&mut raw_data)
        .context("failed to read file to end")?;

    let decrypted: Vec<u8> = decrypt(raw_data)
        .context("failed to decrypt")?;

    let config: Configuration = standard();
    let decoded: T = decode_from_slice(&decrypted, config)
        .context("failed to decode / serialize")?.0;

    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use crate::bin_storage::{write, read};
    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestData {
        data: Vec<u16>,
    }

    #[test]
    fn write_read() -> Result<()> {
        let test_data: TestData = TestData { data: vec![123] };
        let filepath: &str = "write_read.rask";

        write(filepath, test_data.clone())?;

        let read_testdata: TestData = read(filepath)?;
        std::fs::remove_file(filepath)?;

        assert_eq!(test_data, read_testdata, "should be the same");
        Ok(())
    }

    #[test]
    fn empty_tasklist() -> Result<()> {
        let test_data: TestData = TestData { data: vec![] };
        let filepath: &str = "empty_tasklist.rask";

        write(filepath, test_data.clone())?;
        let read_testdata: TestData = read(filepath)?;

        assert_eq!(test_data, read_testdata, "should be the same");
        std::fs::remove_file(filepath)?;
        Ok(())
    }

    #[test]
    fn read_nonexistent_file() -> Result<()> {
        let filepath: &str = "non_existent.rask";
        let result: Result<TestData, anyhow::Error> = read(filepath);

        assert!(result.is_err(), "reading a non-existent file should yield an error");
        Ok(())
    }

    #[test]
    fn read_corrupted_file() -> Result<()> {
        let filepath: &str = "corrupted.rask";
        std::fs::write(filepath, b"not encrypted or valid data")?;

        let result: Result<TestData, anyhow::Error> = read(filepath);

        assert!(result.is_err(), "should fail to decrypt and decode");
        std::fs::remove_file(filepath)?;
        Ok(())
    }

    #[test]
    fn large_taskfile() -> Result<()> {
        let test_data: TestData = TestData { data: (0..65535).collect() };
        let filepath: &str = "large_taskfile.rask";

        write(filepath, test_data.clone())?;
        let read_testdata: TestData = read(filepath)?;

        assert_eq!(test_data, read_testdata, "should be the same");
        std::fs::remove_file(filepath)?;
        Ok(())
    }
}
