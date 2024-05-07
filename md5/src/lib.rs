//! Assembly implementation of the [MD5] compression function.
//!
//! This crate is not intended for direct use, most users should
//! prefer the [`md5`] crate with enabled `asm` feature instead.
//!
//! Only x86 and x86-64 architectures are currently supported.
//!
//! [MD5]: https://en.wikipedia.org/wiki/MD5
//! [`md5`]: https://crates.io/crates/md5

#![no_std]
#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
compile_error!("crate can only be used on x86 and x86-64 architectures");

#[cfg(target_os = "windows")]
compile_error!("crate does not support Windows targets");

#[link(name = "md5", kind = "static")]
extern "C" {
    fn md5_compress(state: &mut [u32; 4], block: &[u8; 64]);
}

/// Safe wrapper around assembly implementation of MD5 compression function
#[inline]
pub fn compress(state: &mut [u32; 4], blocks: &[[u8; 64]]) {
    for block in blocks {
        unsafe {
            md5_compress(state, block);
        }
    }
}
