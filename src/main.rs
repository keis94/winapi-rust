use std::ptr;
use windows::Win32::System::Registry::{self, RegOpenKeyExA, RegQueryValueExA};
use windows::{s, Win32};

fn main() {
    unsafe {
        let mut hkey = Registry::HKEY(0);
        let lpreserved: *mut u32 = ptr::null_mut();
        let mut reg_value_type = Registry::REG_DWORD;
        let mut lpcbdata: u32 = 0;

        let result = RegOpenKeyExA(
            Registry::HKEY_CURRENT_USER,
            s!("Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
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

        let result = RegQueryValueExA(
            hkey,
            s!(""),
            Some(lpreserved),
            Some(&mut reg_value_type),
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
        println!("success lpcbdata = {:?}", lpcbdata);

        let mut lpdata = vec![0; lpcbdata as usize];
        let result = RegQueryValueExA(
            hkey,
            s!(""),
            Some(lpreserved),
            Some(&mut reg_value_type),
            Some(lpdata.as_mut_ptr()),
            Some(&mut lpcbdata),
        );
        match result {
            Win32::Foundation::NO_ERROR => {
                println!("lpdata: {:?}", std::str::from_utf8(&lpdata).unwrap());
            }
            error => {
                println!("error on RegQueryValueExA: {:?}", error);
            }
        }
    }
}
