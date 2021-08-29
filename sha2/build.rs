use std::collections::HashSet;

fn main() {
    use std::env;

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_vendor = env::var("CARGO_CFG_TARGET_VENDOR").unwrap_or_default();
    // panic!("{}", env::var("CARGO_CFG_TARGET_ARCH").unwrap());
    let features: HashSet<String> = env::var("CARGO_CFG_TARGET_FEATURE")
        .unwrap_or_default()
        .split(',')
        .map(|x| x.to_string())
        .collect();

    let mut build256 = cc::Build::new();
    let (sha256_path, sha512_path) = if target_arch == "x86" {
        ("src/sha256_x86.S", "src/sha512_x86.S")
    } else if target_arch == "x86_64" {
        // using aes-ni, cause it's fastest
        if features.contains("aes") {
            ("src/sha256_x64_ni.S", "src/sha512_x64.S")
        } else if features.contains("avx2") {
            ("src/sha256_x64_avx2.S", "src/sha512_x64_avx2.S")
        } else {
            ("src/sha256_x64.S", "src/sha512_x64.S")
        }
    } else if target_arch == "aarch64" && target_vendor == "apple" {
        build256.flag("-march=armv8-a+crypto");
        ("src/sha256_aarch64_apple.S", "")
    } else if target_arch == "aarch64" {
        build256.flag("-march=armv8-a+crypto");
        ("src/sha256_aarch64.S", "")
    } else {
        panic!("Unsupported target architecture");
    };

    if target_arch != "aarch64" {
        cc::Build::new()
            .flag("-c")
            .file(sha512_path)
            .compile("libsha512.a");
    }
    build256.flag("-c").file(sha256_path).compile("libsha256.a");
}
