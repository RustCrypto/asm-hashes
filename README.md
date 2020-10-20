# RustCrypto: ASM hashes ![Rust Version][rustc-image] [![Project Chat][chat-image]][chat-link]

Assembly implementations of hash functions core functionality based on code from
[Project Nayuki](https://www.nayuki.io/).

Crates in this repository provide only core compression functions, for full hash
functionality please refer to the crates from
[RustCrypto/hashes](https://github.com/RustCrypto/hashes) repository. With
enabled `asm` feature `md5`, `sha-1`, `sha2` and `whirlpool` crates will use
code from this repository.

## Supported Platforms

All crates are tested on the following platforms:

- Linux (32-bit and 64-bit x86)
- Windows (64-bit x86, GNU only)
- ARM64 (except `md5`, which is x86 only)

Windows MSVC builds are known to be broken. See [#17].

## Minimum Supported Rust Version

All crates in this repository support **Rust 1.43** or higher.

In the future when the minimum supported Rust version is changed,
it will be accompanied by a minor version bump.

## License

All crates licensed under the [MIT license](http://opensource.org/licenses/MIT).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

[//]: # (badges)

[rustc-image]: https://img.shields.io/badge/rustc-1.43+-blue.svg
[chat-image]: https://img.shields.io/badge/zulip-join_chat-blue.svg
[chat-link]: https://rustcrypto.zulipchat.com/#narrow/stream/260041-hashes

[//]: # (general links)

[#17]: https://github.com/RustCrypto/asm-hashes/issues/17
