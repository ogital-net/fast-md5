//! # fast-md5
//!
//! A small MD5 implementation with hand-written assembly cores for
//! `x86_64` and `aarch64`, plus a portable Rust fallback for every other
//! target. The assembly was ported from
//! [animetosho/md5-optimisation](https://github.com/animetosho/md5-optimisation)
//! (released into the public domain by the author; see
//! [discussion #4](https://github.com/animetosho/md5-optimisation/discussions/4)).
//!
//! On Apple Silicon and modern x86_64 the per-block compression is
//! within ~1 % of AWS-LC's hand-tuned C. End-to-end in HMAC-MD5
//! workloads (e.g. RADIUS Message-Authenticator), the all-Rust call
//! path beats AWS-LC by ~18 % thanks to cross-call inlining and a
//! precomputed-state HMAC structure (see below).
//!
//! ## Security warning
//!
//! MD5 is **cryptographically broken** — it is trivially vulnerable to
//! collision attacks and must not be used for digital signatures,
//! certificate fingerprints, or any other security-sensitive integrity
//! check. HMAC-MD5 is also discouraged for new designs; this crate
//! exposes [`HmacMd5`] solely to support legacy protocols (RADIUS,
//! CHAP, certain SASL/SIP digests) and non-cryptographic uses such as
//! deduplication and checksumming.
//!
//! ## Quick start
//!
//! ```
//! let digest = fast_md5::digest(b"The quick brown fox jumps over the lazy dog");
//! assert_eq!(
//!     digest,
//!     [
//!         0x9e, 0x10, 0x7d, 0x9d, 0x37, 0x2b, 0xb6, 0x82,
//!         0x6b, 0xd8, 0x1d, 0x35, 0x42, 0xa4, 0x19, 0xd6,
//!     ],
//! );
//! ```
//!
//! Streaming MD5:
//!
//! ```
//! let mut h = fast_md5::Md5::new();
//! h.update(b"The quick brown fox ");
//! h.update(b"jumps over the lazy dog");
//! assert_eq!(
//!     h.finalize(),
//!     [
//!         0x9e, 0x10, 0x7d, 0x9d, 0x37, 0x2b, 0xb6, 0x82,
//!         0x6b, 0xd8, 0x1d, 0x35, 0x42, 0xa4, 0x19, 0xd6,
//!     ],
//! );
//! ```
//!
//! Streaming HMAC-MD5 (RFC 2104):
//!
//! ```
//! let mut h = fast_md5::HmacMd5::new(b"Jefe");
//! h.update(b"what do ya want ");
//! h.update(b"for nothing?");
//! assert_eq!(
//!     h.finalize(),
//!     [
//!         0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5, 0x03,
//!         0xea, 0xa8, 0x6e, 0x31, 0x0a, 0x5d, 0xb7, 0x38,
//!     ],
//! );
//! ```
//!
//! ## `no_std`
//!
//! The crate is `#![no_std]` and performs no heap allocation. All
//! buffers (the 64-byte block buffer, the 4-word state, the HMAC
//! ipad/opad scratch) live inline in the user's value or on the
//! caller's stack.
//!
//! ## Cargo features
//!
//! - **`force-fallback`** — disable the architecture-specific assembly
//!   backends and route [`transform`] through the portable Rust
//!   [`fallback`](crate) implementation on every target. Intended for
//!   CI coverage of the fallback on assembly hosts and for downstream
//!   debugging; not recommended for production use on `x86_64` /
//!   `aarch64` (the fallback is correct but materially slower).
//!
//! ## Design notes
//!
//! The crate is small enough to read end-to-end, but a few choices are
//! worth flagging because they're load-bearing for performance and
//! were arrived at empirically.
//!
//! ### Architecture dispatch
//!
//! [`transform`] is a `cfg`-dispatched shim that routes to one of
//! three backends, all with identical semantics:
//!
//! - **`x86_64`**: a single monolithic `asm!` block per 64-byte block,
//!   ported from animetosho's "NoLEA" sequence. It uses `add` chains
//!   instead of `lea` to keep the critical path on the integer ALUs,
//!   which is faster on every x86_64 microarchitecture from Haswell
//!   onward.
//! - **`aarch64`**: per-round Rust expressions with a one-line `asm!`
//!   block for the rotate. LLVM produces nearly the same code as a
//!   monolithic asm block here because AArch64's three-operand ALU
//!   (no destination clobber) and free shifts give the register
//!   allocator more freedom; the inline `ror` exists only to pin a
//!   concrete 32-bit register at each round boundary, which guides
//!   scheduling.
//! - **fallback**: portable safe Rust used on all other targets *and*
//!   compiled (but not linked) under `cfg(test)` everywhere, so its
//!   `transform` can be cross-checked against the assembly backends
//!   on every supported host.
//!
//! ### Inlining policy
//!
//! - The architecture-specific `transform` is `#[inline(always)]` —
//!   it must fuse with [`Md5::update`]'s per-block loop or LLVM
//!   leaves the state in memory between blocks.
//! - [`Md5::update`] and [`Md5::finalize`] are plain `#[inline]` —
//!   their bodies are large once `transform` inlines (~700
//!   instructions on aarch64), and forcing inline at every call site
//!   measurably regresses I-cache-bound workloads (HMAC chains, etc.).
//!   Plain `#[inline]` exposes MIR for cross-crate inlining and lets
//!   LLVM's size heuristic decide.
//! - [`Md5::new`] and [`digest`] are `#[inline(always)]` — trivial
//!   wrappers; forcing inline lets the IV propagate as register
//!   immediates and lets known-length one-shots collapse `finalize`'s
//!   padding into constants.
//!
//! ### Block buffer uses `MaybeUninit`
//!
//! [`Md5`]'s 64-byte partial-block buffer is `[MaybeUninit<u8>; 64]`
//! rather than `[u8; 64]`. Construction is therefore a no-op (no
//! 64-byte zero fill on every `Md5::new()`), and bytes are only read
//! after they have been written. This matters when the caller does
//! many short hashes per second — RADIUS again — because the cost of
//! initialising a `Md5` becomes negligible relative to the
//! compression itself.
//!
//! ### `HmacMd5` precomputes ipad/opad states
//!
//! [`HmacMd5::new`] runs the ipad and opad block compressions
//! immediately and stores **only** the resulting `[u32; 4]` states
//! (32 bytes total). Steady-state, [`update`](HmacMd5::update) is
//! pure delegation to the inner [`Md5`], and
//! [`finalize`](HmacMd5::finalize) costs exactly **two** extra
//! compressions on top of the message work (inner tail + outer
//! tail). This is the same shape as AWS-LC's `HMAC_CTX` and is what
//! gives the ~18 % end-to-end win in HMAC-bound workloads.
//!
//! ### No volatile key zeroization
//!
//! Neither [`Md5`] nor [`HmacMd5`] performs `write_volatile`-style
//! scrubbing of stack scratch on drop. The transient ipad/opad XOR
//! blocks inside [`HmacMd5::new`] are recoverable only during the
//! lifetime of that call, and the persistent struct holds digests of
//! the key (one-way) rather than the key itself. Callers with
//! stricter threat models (FIPS, processes that emit core dumps,
//! protocols where memory-disclosure bugs are realistic) should
//! wrap their key in [`zeroize::Zeroizing`](https://docs.rs/zeroize)
//! at the call site; this crate cannot meaningfully protect a key
//! that the caller is already holding in long-lived memory.
//!
//! Skipping the volatile writes also keeps the hot path free of
//! optimization barriers, which is part of why the all-Rust HMAC
//! path beats the FFI'd C implementations.

#![no_std]
#![deny(missing_docs)]

/// MD5 compresses 64-byte blocks.
pub const BLOCK_SIZE: usize = 64;

/// MD5 produces a 16-byte digest.
pub const DIGEST_LENGTH: usize = 16;

const STATE_WORDS: usize = 4;

/// Standard MD5 initialization vector (RFC 1321 §3.3).
const IV: [u32; STATE_WORDS] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

#[cfg(all(target_arch = "aarch64", not(feature = "force-fallback")))]
mod aarch64;
// The fallback module is compiled when:
//   - the target has no assembly backend, or
//   - the `force-fallback` feature is enabled (CI / debugging), or
//   - we are running tests (so its in-module RFC 1321 vectors run on
//     every host, regardless of the active backend).
#[cfg(any(
    test,
    feature = "force-fallback",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
mod fallback;
#[cfg(all(target_arch = "x86_64", not(feature = "force-fallback")))]
mod x86_64;

mod hmac;
pub use hmac::HmacMd5;

/// Streaming MD5 hasher.
///
/// Buffers partial blocks internally and dispatches to the
/// architecture-specific compression function on every full 64-byte
/// block. Call [`Md5::finalize`] to consume the hasher and obtain the
/// 16-byte digest.
pub struct Md5 {
    state: [u32; STATE_WORDS],
    /// Number of bytes processed so far (used for final length encoding).
    count: u64,
    /// Partial block buffer. Only the first `buf_len` bytes are
    /// initialized at any given moment; the tail is untouched
    /// uninitialized memory.
    buf: [core::mem::MaybeUninit<u8>; BLOCK_SIZE],
    /// Number of bytes currently in `buf`.
    buf_len: usize,
}

#[allow(clippy::new_without_default)]
impl Md5 {
    /// Construct a new hasher initialized with the standard MD5 IV.
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            state: IV,
            count: 0,
            // Buffer is left uninitialized; `update`/`finalize` only
            // read bytes after writing them.
            buf: [const { core::mem::MaybeUninit::<u8>::uninit() }; BLOCK_SIZE],
            buf_len: 0,
        }
    }

    /// Construct a hasher resuming from a precomputed `state` that has
    /// already absorbed `count_bytes` bytes (which must be a multiple
    /// of [`BLOCK_SIZE`]). Used by [`HmacMd5`] to install the
    /// post-ipad / post-opad inner states without rerunning the
    /// compression on the key block at every operation.
    #[inline(always)]
    pub(crate) fn from_parts(state: [u32; STATE_WORDS], count_bytes: u64) -> Self {
        debug_assert!(count_bytes % (BLOCK_SIZE as u64) == 0);
        Self {
            state,
            count: count_bytes,
            buf: [const { core::mem::MaybeUninit::<u8>::uninit() }; BLOCK_SIZE],
            buf_len: 0,
        }
    }

    /// Absorb additional input. May be called any number of times.
    ///
    /// Annotated `#[inline]` (not `inline(always)`): the body is large
    /// once the architecture-specific `transform` inlines into it, and
    /// forcing inline at every HMAC call site causes I-cache pressure
    /// that measurably regresses real-world workloads. `#[inline]`
    /// still exposes MIR for cross-crate inlining when LLVM's size
    /// heuristic decides the win is worth it.
    #[inline]
    pub fn update(&mut self, mut data: &[u8]) {
        self.count = self.count.wrapping_add(data.len() as u64);

        // Fill partial buffer first.
        if self.buf_len > 0 {
            let need = BLOCK_SIZE - self.buf_len;
            let take = need.min(data.len());
            // SAFETY: `take <= need` and `buf_len + need == BLOCK_SIZE`,
            // so the destination range is inside `buf`. `MaybeUninit<u8>`
            // has the same layout as `u8`, so we can write into it via a
            // byte pointer.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    data.as_ptr(),
                    self.buf.as_mut_ptr().add(self.buf_len).cast::<u8>(),
                    take,
                );
            }
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == BLOCK_SIZE {
                // SAFETY: all 64 bytes of `buf` are now initialized.
                let block: &[u8; BLOCK_SIZE] =
                    unsafe { &*(self.buf.as_ptr().cast::<[u8; BLOCK_SIZE]>()) };
                transform(&mut self.state, block);
                self.buf_len = 0;
            }
        }

        // Process full blocks directly from `data`.
        while data.len() >= BLOCK_SIZE {
            let block: &[u8; BLOCK_SIZE] = unsafe { &*(data.as_ptr().cast::<[u8; BLOCK_SIZE]>()) };
            transform(&mut self.state, block);
            data = &data[64..];
        }

        // Save remainder.
        if !data.is_empty() {
            // SAFETY: `data.len() < BLOCK_SIZE` (loop above drained
            // full blocks), so this write stays inside `buf`.
            unsafe {
                core::ptr::copy_nonoverlapping(
                    data.as_ptr(),
                    self.buf.as_mut_ptr().cast::<u8>(),
                    data.len(),
                );
            }
            self.buf_len = data.len();
        }
    }

    /// Consume the hasher and return the 16-byte digest.
    ///
    /// See [`Md5::update`] for the rationale behind plain `#[inline]`.
    #[inline]
    pub fn finalize(mut self) -> [u8; DIGEST_LENGTH] {
        // Append bit '1' (0x80 byte), then zero-pad to 56 mod 64, then 64-bit LE bit count.
        let bit_count = self.count.wrapping_mul(8);
        // SAFETY: `buf_len <= BLOCK_SIZE - 1` on entry to `finalize`
        // (a full block would have been flushed by `update`), so this
        // write stays inside `buf`.
        unsafe {
            self.buf
                .as_mut_ptr()
                .add(self.buf_len)
                .cast::<u8>()
                .write(0x80);
        }
        self.buf_len += 1;

        if self.buf_len > 56 {
            // Need an extra block: zero-pad the rest of this one and
            // process it; the length encoding goes into the next block.
            // SAFETY: writes `BLOCK_SIZE - buf_len` zero bytes starting
            // at offset `buf_len`, staying inside `buf`.
            unsafe {
                core::ptr::write_bytes(
                    self.buf.as_mut_ptr().add(self.buf_len).cast::<u8>(),
                    0,
                    BLOCK_SIZE - self.buf_len,
                );
            }
            // SAFETY: all 64 bytes of `buf` are initialized.
            let block: &[u8; BLOCK_SIZE] =
                unsafe { &*(self.buf.as_ptr().cast::<[u8; BLOCK_SIZE]>()) };
            transform(&mut self.state, block);
            self.buf_len = 0;
        }

        // Zero-pad up to byte 56, then write the bit count.
        // SAFETY: `buf_len <= 56`, so the zero fill and length write
        // jointly cover bytes `buf_len..64` inside `buf`.
        unsafe {
            core::ptr::write_bytes(
                self.buf.as_mut_ptr().add(self.buf_len).cast::<u8>(),
                0,
                56 - self.buf_len,
            );
            core::ptr::copy_nonoverlapping(
                bit_count.to_le_bytes().as_ptr(),
                self.buf.as_mut_ptr().add(56).cast::<u8>(),
                8,
            );
        }
        // SAFETY: all 64 bytes of `buf` are initialized.
        let block: &[u8; 64] = unsafe { &*(self.buf.as_ptr().cast::<[u8; 64]>()) };
        transform(&mut self.state, block);

        let mut digest = [0u8; DIGEST_LENGTH];
        for (i, word) in self.state.iter().enumerate() {
            digest[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        digest
    }
}

/// Compress one 64-byte block into the running MD5 state.
///
/// This is the architecture-dispatch entry point used by [`Md5::update`]
/// and [`Md5::finalize`]. It is exposed for callers that already have
/// the message-length padding handled themselves (for example, custom
/// streaming wrappers). Most users should prefer [`digest`] or the
/// [`Md5`] type.
#[inline]
pub fn transform(state: &mut [u32; STATE_WORDS], block: &[u8; BLOCK_SIZE]) {
    #[cfg(all(target_arch = "x86_64", not(feature = "force-fallback")))]
    {
        x86_64::transform(state, block);
    }
    #[cfg(all(target_arch = "aarch64", not(feature = "force-fallback")))]
    {
        aarch64::transform(state, block);
    }
    #[cfg(any(
        feature = "force-fallback",
        not(any(target_arch = "x86_64", target_arch = "aarch64"))
    ))]
    {
        fallback::transform(state, block);
    }
}

/// One-shot convenience: hash `data` and return the digest.
#[inline(always)]
pub fn digest(data: &[u8]) -> [u8; DIGEST_LENGTH] {
    let mut m = Md5::new();
    m.update(data);
    m.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    // (input, expected hex digest) — RFC 1321 §A.5 test suite plus a few
    // long inputs that exercise the multi-block path.
    const VECTORS: &[(&[u8], &str)] = &[
        (b"", "d41d8cd98f00b204e9800998ecf8427e"),
        (b"a", "0cc175b9c0f1b6a831c399e269772661"),
        (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
        (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        (
            b"abcdefghijklmnopqrstuvwxyz",
            "c3fcd3d76192e4007dfb496cca67e13b",
        ),
        (
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "d174ab98d277d9f5a5611c2c9f419d9f",
        ),
        (
            b"12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "57edf4a22be3c955ac49da2e2107b67a",
        ),
    ];

    fn hex(bytes: &[u8]) -> [u8; 32] {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = [0u8; 32];
        for (i, b) in bytes.iter().enumerate() {
            out[i * 2] = HEX[(b >> 4) as usize];
            out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
        }
        out
    }

    #[test]
    fn rfc1321_vectors_oneshot() {
        for (input, want) in VECTORS {
            let got = digest(input);
            assert_eq!(
                core::str::from_utf8(&hex(&got)).unwrap(),
                *want,
                "input len {}",
                input.len()
            );
        }
    }

    #[test]
    fn rfc1321_vectors_streaming_byte_by_byte() {
        for (input, want) in VECTORS {
            let mut h = Md5::new();
            for chunk in input.chunks(1) {
                h.update(chunk);
            }
            assert_eq!(
                core::str::from_utf8(&hex(&h.finalize())).unwrap(),
                *want,
                "streaming input len {}",
                input.len()
            );
        }
    }

    #[test]
    fn rfc1321_vectors_streaming_odd_chunks() {
        // Use a chunk size that doesn't divide BLOCK_SIZE evenly to
        // exercise the buffer / boundary code paths.
        for (input, want) in VECTORS {
            let mut h = Md5::new();
            for chunk in input.chunks(13) {
                h.update(chunk);
            }
            assert_eq!(core::str::from_utf8(&hex(&h.finalize())).unwrap(), *want,);
        }
    }

    #[test]
    fn million_a_test_vector() {
        // RFC 1321 §A.5: MD5("a" * 1_000_000) = 7707d6ae4e027c70eea2a935c2296f21
        let mut h = Md5::new();
        let chunk = [b'a'; 1024];
        for _ in 0..1000 {
            h.update(&chunk[..1000]);
        }
        let got = h.finalize();
        assert_eq!(
            core::str::from_utf8(&hex(&got)).unwrap(),
            "7707d6ae4e027c70eea2a935c2296f21",
        );
    }

    // The active `transform` is the architecture-specific one when built
    // on x86_64 or aarch64; on other targets it is the fallback. Either
    // way, this test compares it block-for-block against the always-
    // available portable fallback implementation, giving us cross-
    // implementation cross-checking on the assembly hosts.
    #[test]
    fn transform_matches_fallback_on_random_blocks() {
        let seed: u64 = 0x1234_5678_9abc_def0;
        let mut rng_state = seed;
        let mut next = || -> u64 {
            // xorshift64*
            rng_state ^= rng_state << 13;
            rng_state ^= rng_state >> 7;
            rng_state ^= rng_state << 17;
            rng_state.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };

        for _ in 0..256 {
            let mut block = [0u8; BLOCK_SIZE];
            for chunk in block.chunks_mut(8) {
                chunk.copy_from_slice(&next().to_le_bytes());
            }
            let init_state = [next() as u32, next() as u32, next() as u32, next() as u32];

            let mut s_active = init_state;
            transform(&mut s_active, &block);

            let mut s_ref = init_state;
            fallback::transform(&mut s_ref, &block);

            assert_eq!(s_active, s_ref);
        }
    }
}
