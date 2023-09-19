//! Assembly implementation of the [SHA-1] compression function.
//!
//! This crate is not intended for direct use, most users should
//! prefer the [`sha-1`] crate with enabled `asm` feature instead.
//!
//! Only x86, x86-64, AArch64 and LoongArch64 architectures are currently supported.
//!
//! [SHA-1]: https://en.wikipedia.org/wiki/SHA-1
//! [`sha-1`]: https://crates.io/crates/sha-1

#![no_std]
#[cfg(not(any(
    target_arch = "x86_64",
    target_arch = "x86",
    target_arch = "aarch64",
    target_arch = "loongarch64"
)))]
compile_error!("crate can only be used on x86, x86_64, AArch64 and LoongArch64 architectures");

#[link(name = "sha1", kind = "static")]
extern "C" {
    fn sha1_compress(state: &mut [u32; 5], block: &[u8; 64]);
}

/// Safe wrapper around assembly implementation of SHA-1 compression function
#[inline]
pub fn compress(state: &mut [u32; 5], blocks: &[[u8; 64]]) {
    for block in blocks {
        unsafe {
            sha1_compress(state, block);
        }
    }
}
