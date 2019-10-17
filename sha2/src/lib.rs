//! Assembly implementation of [SHA-2][1] compression functions.
//!
//! For full SHA-2 hash functions with this implementation of compression
//! functions use [sha-2](https://crates.io/crates/sha-2) crate with
//! the enabled "asm" feature.
//!
//! Only x86 and x86-64 architectures are currently supported.
//!
//! [1]: https://en.wikipedia.org/wiki/SHA-2

#![no_std]
#[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
compile_error!("crate can only be used on x86 and x86-64 architectures");

#[link(name = "sha256_shani", kind = "static")]
extern "C" {
    fn sha256_process_x86(state: &mut [u32; 8], block: *const u8, length: u32);
}

#[inline]
pub fn compress256_shani(state: &mut [u32; 8], block: &[u8; 64]) {
    unsafe { sha256_process_x86(state, block.as_ptr(), block.len() as u32) }
}

#[link(name = "sha256", kind = "static")]
extern "C" {
    fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]);
}

use core::arch::x86_64::CpuidResult;
#[inline]
pub fn get_cpuid(info: u32) -> CpuidResult {
    use core::arch::x86_64::__cpuid_count;
    unsafe { __cpuid_count(info, 0) }
}

/// Safe wrapper around assembly implementation of SHA256 compression function
#[inline]
pub fn compress256(state: &mut [u32; 8], block: &[u8; 64]) {
    let x = get_cpuid(0x7);
    if x.ebx & (1 << 29) != 0 {
        compress256_shani(state, block);
    } else {
        unsafe { sha256_compress(state, block) };
    }
}

#[link(name = "sha512", kind = "static")]
extern "C" {
    fn sha512_compress(state: &mut [u64; 8], block: &[u8; 128]);
}

/// Safe wrapper around assembly implementation of SHA512 compression function
#[inline]
pub fn compress512(state: &mut [u64; 8], block: &[u8; 128]) {
    unsafe { sha512_compress(state, block) }
}
