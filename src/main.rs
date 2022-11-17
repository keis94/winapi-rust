use std::ffi::CString;
use std::ptr;
use windows;
use windows::core::PCSTR;
use windows::Win32;
use windows::Win32::System::Registry::{self, RegOpenKeyExA, RegQueryValueExA};

fn query_registry_value(
    subkey: &str,
    value: &str,
    mut value_type: Registry::REG_VALUE_TYPE,
) -> Result<String, windows::core::Error> {
    // CString must be bound to prevent buffer from being dropped.
    let subkey = CString::new(subkey).ok().unwrap();
    let psubkey = PCSTR::from_raw(subkey.as_ptr() as *const u8);

    let value = CString::new(value).ok().unwrap();
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
    if let Err(error) = result.ok() {
        return Err(error);
    }

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
    if let Err(error) = result.ok() {
        return Err(error);
    }

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
            let cstr = match CString::from_vec_with_nul(lpdata) {
                Ok(s) => s,
                Err(e) => return Err(e),
            };
            Ok(cstr.into_string().ok().unwrap())
        }
        error => Err(error.ok().unwrap_err()),
    }
}

fn main() {
    let subkey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    let value = "";
    let value_type = Registry::REG_SZ;

    match query_registry_value(subkey, value, value_type) {
        Ok(data) => {
            println!("subkey: {:?}", subkey);
            println!("value: {:?}", value);
            println!("data: {:?}", data);
        }
        Err(error) => {
            println!("{} {}", error.code(), error.message())
        }
    }
}
