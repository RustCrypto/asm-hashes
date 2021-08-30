fn main() {
    use std::env;

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_vendor = env::var("CARGO_CFG_TARGET_VENDOR").unwrap_or_default();

    let mut build256 = cc::Build::new();
    let (sha256_path, sha512_path) = if target_arch == "x86" {
        (["src/sha256_x86.S"].iter(), ["src/sha512_x86.S"].iter())
    } else if target_arch == "x86_64" {
        let sha512 = ["src/sha512_x64_avx2.S", "src/sha512_x64.S"].iter();
        // Prioritizing sha-ni, cause it's fastest
        let sha256 = [
            "src/sha256_x64_ni.S",
            "src/sha256_x64_avx2.S",
            "src/sha256_x64.S",
        ]
        .iter();
        (sha256, sha512)
    } else if target_arch == "aarch64" && target_vendor == "apple" {
        build256.flag("-march=armv8-a+crypto");
        (["src/sha256_aarch64_apple.S"].iter(), [""].iter())
    } else if target_arch == "aarch64" {
        build256.flag("-march=armv8-a+crypto");
        (["src/sha256_aarch64.S"].iter(), [""].iter())
    } else {
        panic!("Unsupported target architecture");
    };

    if target_arch != "aarch64" {
        cc::Build::new()
            .flag("-c")
            .files(sha512_path)
            .compile("libsha512.a");
    }
    build256
        .flag("-c")
        .files(sha256_path)
        .compile("libsha256.a");
}
