extern crate cc;

fn main() {
    let (sha256_path, sha512_path) = if cfg!(target_arch = "x86") {
        ("src/sha256_x86.S", "src/sha512_x86.S")
    } else if cfg!(target_arch = "x86_64") {
        ("src/sha256_x64.S", "src/sha512_x64.S")
    } else {
        panic!("Unsupported target architecture");
    };
    cc::Build::new()
        .flag("-c")
        .file(sha256_path)
        .compile("libsha256.a");
    cc::Build::new()
        .flag("-c")
        .file(sha512_path)
        .compile("libsha512.a");
    cc::Build::new()
        .flag("-c")
        .flag("-msse4.1")
        .flag("-msha")
        .file("src/sha256_x64.c")
        .compile("libsha256_shani.a");
}
