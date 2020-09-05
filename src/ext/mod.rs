//!
//! A module containing the implementation of extensions for [`fs::File`]s and [`fs::DirEntry`]s
//! that allows windows users to get and set security information.
//!

use std::{fs, fmt, io, ptr};
use std::os::windows::io::AsRawHandle;
use std::os::windows::ffi::OsStrExt;

use winapi::um::accctrl::SE_FILE_OBJECT;
use winapi::um::winnt::{SID, ACL, SECURITY_DESCRIPTOR, OWNER_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION, GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_ATTRIBUTE_NORMAL};
use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
use winapi::um::aclapi::{GetSecurityInfo, SetSecurityInfo};
use std::io::{Error, ErrorKind};
use winapi::ctypes::c_void;
use std::ffi::OsStr;

#[cfg(test)]
mod test;

/// Copied from std::sys::windows. Finds a needle u16 in a haystack.
pub fn unrolled_find_u16s(needle: u16, haystack: &[u16]) -> Option<usize> {
    let ptr = haystack.as_ptr();
    let mut start = &haystack[..];

    // For performance reasons unfold the loop eight times.
    while start.len() >= 8 {
        macro_rules! if_return {
            ($($n:literal,)+) => {
                $(
                    if start[$n] == needle {
                        return Some((&start[$n] as *const u16 as usize - ptr as usize) / 2);
                    }
                )+
            }
        }

        if_return!(0, 1, 2, 3, 4, 5, 6, 7,);

        start = &start[8..];
    }

    for c in start {
        if *c == needle {
            return Some((c as *const u16 as usize - ptr as usize) / 2);
        }
    }
    None
}

/// Copied from std::sys::windows. Converts an object into a vector of u16,
/// for passing to a wide-string API
fn to_u16s<S: AsRef<OsStr>>(s: S) -> io::Result<Vec<u16>> {
    fn inner(s: &OsStr) -> io::Result<Vec<u16>> {
        let mut maybe_result: Vec<u16> = s.encode_wide().collect();
        if unrolled_find_u16s(0, &maybe_result).is_some() {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "strings passed to WinAPI cannot contain NULs",
            ));
        }
        maybe_result.push(0);
        Ok(maybe_result)
    }
    inner(s.as_ref())
}

/// A struct representing windows security information. Can be used to check the owner
/// of a file or directory, as well as ACL info
#[derive(Clone)]
pub struct Security {
    owner: SID,
    dacl: ACL
}

impl Security {
    // TODO: What methods should this have?
}

impl fmt::Debug for Security {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Security {{ .. }}")
    }
}

/// A trait extending fs::File objects with the ability to get/set security information on
/// windows
pub trait FileExt {

    /// Get the security information about this file
    fn get_security(&self) -> io::Result<Security>;

    /// Set the security information for this file
    fn set_security(&self, sec: Security) -> io::Result<()>;

}

impl FileExt for fs::File {
    fn get_security(&self) -> io::Result<Security> {
        // SAFETY: Both of these values will be initialized by GetSecurityInfo before they may be read
        let usid: *mut SID = ptr::null_mut();
        let dacl: *mut ACL = ptr::null_mut();
        let sec_descriptor: *mut SECURITY_DESCRIPTOR = ptr::null_mut();

        // SAFETY: We perform checks on the return and pointers before they are used
        let result = unsafe { GetSecurityInfo(
            self.as_raw_handle() as _,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION & DACL_SECURITY_INFORMATION,
            &mut (usid as _),
            ptr::null_mut(),
            &mut (dacl as _),
            ptr::null_mut(),
            &mut (sec_descriptor as _)
        ) };

        if result == 0 {
            return Err(Error::last_os_error())
        }

        assert!(!(usid.is_null() || dacl.is_null() || sec_descriptor.is_null()));

        // SAFETY: These are guaranteed valid by the checks above
        Ok(Security {
            owner: unsafe { *usid.clone() },
            dacl: unsafe { *dacl.clone() }
        })
    }

    fn set_security(&self, mut sec: Security) -> io::Result<()> {
        let result = unsafe { SetSecurityInfo(
            self.as_raw_handle() as _,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION & DACL_SECURITY_INFORMATION,
            &mut sec.owner as *mut SID as _,
            ptr::null_mut(),
            &mut sec.dacl as *mut ACL as _,
            ptr::null_mut()
        ) };

        if result == 0 {
            Err(Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

/// A trait extending fs::DirEntry objects with the ability to get/set security information on
/// windows
pub trait DirEntryExt {

    /// Get the security information about this file
    fn get_security(&self) -> io::Result<Security>;

    /// Set the security information for this file
    fn set_security(&self, sec: Security) -> io::Result<()>;
}

fn get_raw_handle(dir: &fs::DirEntry) -> io::Result<*mut c_void> {
    let path = to_u16s(dir.path())?;

    // SAFETY: This DirEntry should be valid from creation, and result will be checked before use
    let handle = unsafe { CreateFileW(
        path.as_ptr(),
        GENERIC_READ,
        FILE_SHARE_READ & FILE_SHARE_WRITE,
        ptr::null_mut(),
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        ptr::null_mut()
    ) };

    if handle.is_null() {
        Err(Error::last_os_error())
    } else {
        Ok(handle)
    }
}

impl DirEntryExt for fs::DirEntry {
    fn get_security(&self) -> io::Result<Security> {
        let handle = get_raw_handle(self)?;

        // SAFETY: Both of these values will be initialized by GetSecurityInfo before they may be read
        let usid: *mut SID = ptr::null_mut();
        let dacl: *mut ACL = ptr::null_mut();
        let sec_descriptor: *mut SECURITY_DESCRIPTOR = ptr::null_mut();

        // SAFETY: We perform checks on the return and pointers before they are used
        let result = unsafe { GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION & DACL_SECURITY_INFORMATION,
            &mut (usid as _),
            ptr::null_mut(),
            &mut (dacl as _),
            ptr::null_mut(),
            &mut (sec_descriptor as _)
        ) };

        if result == 0 {
            return Err(Error::last_os_error())
        }

        assert!(!(usid.is_null() || dacl.is_null() || sec_descriptor.is_null()));

        // SAFETY: These are guaranteed valid by the checks above
        Ok(Security {
            owner: unsafe { *usid.clone() },
            dacl: unsafe { *dacl.clone() }
        })
    }

    fn set_security(&self, mut sec: Security) -> io::Result<()> {
        let handle = get_raw_handle(self)?;

        let result = unsafe { SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION & DACL_SECURITY_INFORMATION,
            &mut sec.owner as *mut SID as _,
            ptr::null_mut(),
            &mut sec.dacl as *mut ACL as _,
            ptr::null_mut()
        ) };

        if result == 0 {
            Err(Error::last_os_error())
        } else {
            Ok(())
        }
    }
}
