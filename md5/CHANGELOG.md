# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.5.2 (2024-05-06)
### Changed
- Emit compilation error when compiled for Windows targets. ([#79])

[#79]: https://github.com/RustCrypto/asm-hashes/pull/79

## 0.5.1 (2023-08-07)
### Changed
- Prefix x86 asm symbols with `_`` on Windows like on Apple ([#61])
- Fix deprecated use of `cc::Build::compile` ([#59])

[#61]: https://github.com/RustCrypto/asm-hashes/pull/61
[#59]: https://github.com/RustCrypto/asm-hashes/pull/59
