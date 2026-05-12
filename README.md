# fast-md5

[![crates.io](https://img.shields.io/crates/v/fast-md5.svg)](https://crates.io/crates/fast-md5)
[![docs.rs](https://docs.rs/fast-md5/badge.svg)](https://docs.rs/fast-md5)
[![license](https://img.shields.io/crates/l/fast-md5.svg)](LICENSE)

A small `#![no_std]` MD5 implementation with hand-written assembly cores
for `x86_64` and `aarch64`, plus a portable Rust fallback for every
other target.

The assembly was ported from
[animetosho/md5-optimisation][upstream], whose author has placed the
original work in the public domain
([discussion #4][public-domain]). This crate is licensed BSD-2-Clause
for the Rust glue and tests; the assembly stanzas inherit their
public-domain status from upstream.

[upstream]: https://github.com/animetosho/md5-optimisation
[public-domain]: https://github.com/animetosho/md5-optimisation/discussions/4

## ⚠️ MD5 is broken for cryptographic use

MD5 is trivially vulnerable to collision attacks and **must not** be
used for digital signatures, certificate fingerprints, password
hashing, or any other security-sensitive integrity check. This crate
exists to support:

- **Legacy protocols** that bake MD5 into their wire format
  (RADIUS, NTLM, parts of TLS 1.0, etc.) — this is the motivating
  use-case.
- **Non-cryptographic** content addressing, deduplication, and
  checksumming where collisions are not adversarial.

For new designs, use BLAKE3 or SHA-256.

## Usage

Add it to your `Cargo.toml`:

```toml
[dependencies]
fast-md5 = "1.0.0"
```

One-shot hashing:

```rust
let digest = fast_md5::digest(b"The quick brown fox jumps over the lazy dog");
assert_eq!(hex::encode(digest), "9e107d9d372bb6826bd81d3542a419d6");
```

Streaming:

```rust
let mut h = fast_md5::Md5::new();
h.update(b"The quick brown fox ");
h.update(b"jumps over the lazy dog");
let digest = h.finalize();
```

## Architecture support

| Target          | Implementation                          |
| --------------- | --------------------------------------- |
| `x86_64`        | Inline assembly (NoLEA + GOpt schedule) |
| `aarch64`       | Inline assembly                         |
| _everything else_ | Portable Rust fallback                |

The compression function is selected at compile time — there is no
runtime dispatch and no feature flags to remember.

## `no_std`

The crate is `#![no_std]` and performs no heap allocation. The
`Md5` state is `<128` bytes and can live on the stack.

## Testing strategy

The fallback (portable Rust) `transform` is compiled in `cfg(test)`
on every target, regardless of host architecture, so that module-level
unit tests of the compression function can run everywhere. On
assembly hosts the test suite cross-checks the active assembly
`transform` against the fallback block-for-block over randomized
inputs.

The full RFC 1321 §A.5 test suite plus the `"a" * 1_000_000` long-input
vector are covered.

```sh
cargo test
```

## Benchmarks

Throughput benchmarks compare `fast-md5` against:

- [`md-5`](https://crates.io/crates/md-5) — the RustCrypto MD5 crate.
- AWS-LC, via the [`aws-lc-sys`](https://crates.io/crates/aws-lc-sys)
  FFI bindings. (`aws-lc-rs` intentionally does not expose MD5 in its
  public API, so the bench links the C entrypoint directly.)

Run them with:

```sh
cargo bench
```

On Apple Silicon (M-series) you should see `fast-md5` come in roughly
on par with AWS-LC and ~5–10% faster than RustCrypto across the
64 B – 1 MiB range. Exact numbers depend on your CPU; criterion
will write per-input HTML reports under `target/criterion/`.

## Acknowledgements

All algorithmic credit belongs to [@animetosho][upstream] for the
optimization work and the public-domain release of the original C
header. This crate is just a faithful port to Rust inline assembly
with some scaffolding around it.

## License

BSD-2-Clause. See [LICENSE](LICENSE).
