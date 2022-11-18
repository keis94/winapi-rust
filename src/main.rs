use anyhow::{anyhow, Context, Result};
use evtx::{EvtxParser, SerializedEvtxRecord};
use serde_json::Value;
use std::ffi::CString;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::ptr;
use windows::core::PCSTR;
use windows::Win32;
use windows::Win32::System::Registry::{self, RegOpenKeyExA, RegQueryValueExA};

fn pick_event_id(event: &SerializedEvtxRecord<Value>) -> i64 {
    event
        .data
        .get("Event")
        .and_then(|e| e.get("System"))
        .and_then(|e| e.get("EventID"))
        .and_then(|e| e.get("#text"))
        .and_then(|e| e.as_i64())
        .unwrap_or(-1)
}

fn write_file(path: &str, buf: &[u8]) -> Result<()> {
    BufWriter::new(File::create(Path::new(path))?).write_all(buf)?;

    Ok(())
}

fn read_eventlog() -> Result<()> {
    let path = PathBuf::from(".\\powershell.evtx");
    let mut parser = EvtxParser::from_path(path)?;
    let powershell_event = parser
        .records_json_value()
        .filter_map(|e| e.ok())
        .filter(|e| pick_event_id(e) == 400)
        .map(|e| e.data)
        .collect::<Vec<Value>>();

    write_file(
        "./powershell.log",
        serde_json::to_string_pretty(&powershell_event)?.as_bytes(),
    )?;

    Ok(())
}

fn query_registry_value(
    subkey: &str,
    value: &str,
    mut value_type: Registry::REG_VALUE_TYPE,
) -> Result<String> {
    // CString must be bound to prevent buffer from being dropped.
    let subkey = CString::new(subkey)
        .ok()
        .context("subkey contains null byte")?;
    let psubkey = PCSTR::from_raw(subkey.as_ptr() as *const u8);

    let value = CString::new(value)
        .ok()
        .context("value contains null byte")?;
    let pvalue = PCSTR::from_raw(value.as_ptr() as *const u8);

    let mut hkey = Registry::HKEY(0);

    let result = unsafe {
        RegOpenKeyExA(
            Registry::HKEY_CURRENT_USER,
            psubkey,
            0,
            Registry::KEY_QUERY_VALUE,
            &mut hkey,
        )
    };
    result.ok().context("Failed to call RegOpenKeyExA")?;

    // Examine data size
    let mut lpcbdata: u32 = 0;
    let result = unsafe {
        RegQueryValueExA(
            hkey,
            pvalue,
            Some(ptr::null_mut()),
            Some(&mut value_type),
            None,
            Some(&mut lpcbdata),
        )
    };
    result.ok().context("Failed to call RegQueryValueExA")?;

    // Query value
    let mut lpdata = vec![0; lpcbdata as usize];
    let result = unsafe {
        RegQueryValueExA(
            hkey,
            pvalue,
            Some(ptr::null_mut()),
            Some(&mut value_type),
            Some(lpdata.as_mut_ptr()),
            Some(&mut lpcbdata),
        )
    };
    match result {
        Win32::Foundation::NO_ERROR => {
            let cstr = CString::from_vec_with_nul(lpdata).context("Invalid data")?;
            Ok(cstr.into_string().context("Failed to decode data")?)
        }
        _ => Err(anyhow!("Failed to call RegQueryValueExA")),
    }
}

fn main() {
    // Reading registry data
    let subkey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    let value = "";
    let value_type = Registry::REG_SZ;

    let data = query_registry_value(subkey, value, value_type);
    match data {
        Ok(data) => {
            println!("subkey: {:?}", subkey);
            println!("value: {:?}", value);
            println!("data: {:?}", data);
        }
        Err(e) => println!("{:?}", e),
    }

    // Extracting Powershell event log (only Event ID = 400) from .evtx file
    if let Err(e) = read_eventlog() {
        eprintln!("{:?}", e)
    }
}
