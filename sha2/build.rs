fn main() {
    use std::env;

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_vendor = env::var("CARGO_CFG_TARGET_VENDOR").unwrap_or_default();
    let target_family = env::var("CARGO_CFG_TARGET_FAMILY").unwrap_or_default();

    let mut build256 = cc::Build::new();
    let (sha256_path, sha512_path) = if target_arch == "x86" {
        ("src/sha256_x86.S", "src/sha512_x86.S")
    } else if target_arch == "x86_64" && target_family == "unix" {
        ("src/sha256_x64.S", "src/sha512_x64.S")
    } else if target_arch == "x86_64" && target_family == "windows" {
        ("src/sha256_x64_masm.asm", "src/sha512_x64_masm.asm")
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
