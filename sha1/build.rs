fn main() {
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_vendor = std::env::var("CARGO_CFG_TARGET_VENDOR").unwrap_or_default();

    let asm_path = if target_arch == "x86" {
        "src/x86.S"
    } else if target_arch == "x86_64" {
        "src/x64.S"
    } else if target_arch == "aarch64" && target_vendor == "apple" {
        "src/aarch64_apple.S"
    } else if target_arch == "aarch64" {
        "src/aarch64.S"
    } else {
        panic!("Unsupported target architecture");
    };
    let mut build = cc::Build::new();
    if target_arch == "aarch64" {
        build.flag("-march=armv8-a+crypto");
    }
    build.flag("-c").file(asm_path).compile("sha1");
}
