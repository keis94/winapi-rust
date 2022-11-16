use std::ffi;
use std::ptr;
use windows::core;
use windows::Win32;
use windows::Win32::System::Registry::{self, RegOpenKeyExA, RegQueryValueExA};

#[no_mangle]
fn string_to_pcstr(s: &str) -> core::PCSTR {
    // windows::s! only accepts literal (like "foo", 1), not &'static str.
    // So manually converting from &str to PCSTR.
    let s = ffi::CString::new(s).expect("CString::new() failes for &str with null byte.");
    // pointer to str is no longer managed, so leak here.
    // It should be freed with CString::from_raw()
    core::PCSTR::from_raw(s.into_raw() as *const u8)
}

fn query_registry_value(
    subkey: &str,
    value: &str,
    mut value_type: Registry::REG_VALUE_TYPE,
) -> Result<String, Win32::Foundation::WIN32_ERROR> {
    let mut hkey = Registry::HKEY(0);

    unsafe {
        let result = RegOpenKeyExA(
            Registry::HKEY_CURRENT_USER,
            string_to_pcstr(subkey),
            0,
            Registry::KEY_QUERY_VALUE,
            &mut hkey,
        );
        if let Err(error) = result.ok() {
            panic!(
                "Failed to call RegOpenKeyExA. Error Code = {}: {}",
                error.code(),
                error.message()
            )
        }

        // Examine data size
        let mut lpcbdata: u32 = 0;
        let result = RegQueryValueExA(
            hkey,
            string_to_pcstr(value),
            Some(ptr::null_mut()),
            Some(&mut value_type),
            None,
            Some(&mut lpcbdata),
        );
        if let Err(error) = result.ok() {
            panic!(
                "Failed to call RegQueryValueExA. Error Code = {}: {}",
                error.code(),
                error.message()
            )
        }

        // Query value
        let mut lpdata = vec![0; lpcbdata as usize];
        let result = RegQueryValueExA(
            hkey,
            string_to_pcstr(value),
            Some(ptr::null_mut()),
            Some(&mut value_type),
            Some(lpdata.as_mut_ptr()),
            Some(&mut lpcbdata),
        );
        match result {
            Win32::Foundation::NO_ERROR => {
                return Ok(String::from_utf8(lpdata).unwrap());
            }
            error => {
                return Err(error);
            }
        }
    }
}

fn main() {
    let subkey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    let value = "";
    let value_type = Registry::REG_SZ;

    match query_registry_value(subkey, value, value_type) {
        Ok(d) => {
            println!("subkey: {}", subkey);
            println!("value: {}", value);
            println!("data: {}", d);
        }
        Err(e) => {
            let e = e.ok().unwrap_err();
            println!("{} {}", e.code(), e.message())
        }
    }
}
