fn main() {
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_family = std::env::var("CARGO_CFG_TARGET_FAMILY").unwrap_or_default();

    let asm_path = if target_arch == "x86" {
        "src/x86.S"
    } else if target_arch == "x86_64" && target_family == "unix" {
        "src/x64.S"
    } else if target_arch == "x86_64" && target_family == "windows" {
        "src/x64_masm.asm"
    } else {
        panic!("Unsupported target architecture");
    };
    cc::Build::new()
        .flag("-c")
        .file(asm_path)
        .compile("libwhirlpool.a");
}
