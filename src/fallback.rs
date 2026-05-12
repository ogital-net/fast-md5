use crate::{BLOCK_SIZE, STATE_WORDS};

const K: [u32; BLOCK_SIZE] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

#[allow(clippy::too_many_lines)] // intentionally monolithic for LLVM; not worth splitting
#[allow(clippy::many_single_char_names)] // a/b/c/d/m are standard MD5 register names
#[allow(clippy::cast_ptr_alignment)] // read_unaligned() is used immediately after the cast
#[inline(always)]
pub(crate) fn transform(state: &mut [u32; STATE_WORDS], block: &[u8; BLOCK_SIZE]) {
    let m = block.as_ptr().cast::<u32>();

    let load = |i: usize| -> u32 {
        // SAFETY: block is 64 bytes, i in 0..16
        u32::from_le(unsafe { m.add(i).read_unaligned() })
    };

    let (a0, b0, c0, d0) = (state[0], state[1], state[2], state[3]);
    let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);

    macro_rules! step {
        (F, $a:expr, $b:expr, $c:expr, $d:expr, $i:expr, $k:expr, $r:expr) => {{
            $a = $a
                .wrapping_add($d ^ ($b & ($c ^ $d)))
                .wrapping_add(load($i))
                .wrapping_add($k);
            $a = $a.rotate_left($r).wrapping_add($b);
        }};
        // G with delayed-B trick: split into (~D & C) + (D & B)
        (G, $a:expr, $b:expr, $c:expr, $d:expr, $i:expr, $k:expr, $r:expr) => {{
            $a = $a
                .wrapping_add((!$d & $c).wrapping_add($d & $b))
                .wrapping_add(load($i))
                .wrapping_add($k);
            $a = $a.rotate_left($r).wrapping_add($b);
        }};
        (H, $a:expr, $b:expr, $c:expr, $d:expr, $i:expr, $k:expr, $r:expr) => {{
            $a = $a
                .wrapping_add($b ^ $c ^ $d)
                .wrapping_add(load($i))
                .wrapping_add($k);
            $a = $a.rotate_left($r).wrapping_add($b);
        }};
        (I, $a:expr, $b:expr, $c:expr, $d:expr, $i:expr, $k:expr, $r:expr) => {{
            $a = $a
                .wrapping_add($c ^ ($b | !$d))
                .wrapping_add(load($i))
                .wrapping_add($k);
            $a = $a.rotate_left($r).wrapping_add($b);
        }};
    }

    step!(F, a, b, c, d, 0, K[0], 7);
    step!(F, d, a, b, c, 1, K[1], 12);
    step!(F, c, d, a, b, 2, K[2], 17);
    step!(F, b, c, d, a, 3, K[3], 22);
    step!(F, a, b, c, d, 4, K[4], 7);
    step!(F, d, a, b, c, 5, K[5], 12);
    step!(F, c, d, a, b, 6, K[6], 17);
    step!(F, b, c, d, a, 7, K[7], 22);
    step!(F, a, b, c, d, 8, K[8], 7);
    step!(F, d, a, b, c, 9, K[9], 12);
    step!(F, c, d, a, b, 10, K[10], 17);
    step!(F, b, c, d, a, 11, K[11], 22);
    step!(F, a, b, c, d, 12, K[12], 7);
    step!(F, d, a, b, c, 13, K[13], 12);
    step!(F, c, d, a, b, 14, K[14], 17);
    step!(F, b, c, d, a, 15, K[15], 22);

    step!(G, a, b, c, d, 1, K[16], 5);
    step!(G, d, a, b, c, 6, K[17], 9);
    step!(G, c, d, a, b, 11, K[18], 14);
    step!(G, b, c, d, a, 0, K[19], 20);
    step!(G, a, b, c, d, 5, K[20], 5);
    step!(G, d, a, b, c, 10, K[21], 9);
    step!(G, c, d, a, b, 15, K[22], 14);
    step!(G, b, c, d, a, 4, K[23], 20);
    step!(G, a, b, c, d, 9, K[24], 5);
    step!(G, d, a, b, c, 14, K[25], 9);
    step!(G, c, d, a, b, 3, K[26], 14);
    step!(G, b, c, d, a, 8, K[27], 20);
    step!(G, a, b, c, d, 13, K[28], 5);
    step!(G, d, a, b, c, 2, K[29], 9);
    step!(G, c, d, a, b, 7, K[30], 14);
    step!(G, b, c, d, a, 12, K[31], 20);

    step!(H, a, b, c, d, 5, K[32], 4);
    step!(H, d, a, b, c, 8, K[33], 11);
    step!(H, c, d, a, b, 11, K[34], 16);
    step!(H, b, c, d, a, 14, K[35], 23);
    step!(H, a, b, c, d, 1, K[36], 4);
    step!(H, d, a, b, c, 4, K[37], 11);
    step!(H, c, d, a, b, 7, K[38], 16);
    step!(H, b, c, d, a, 10, K[39], 23);
    step!(H, a, b, c, d, 13, K[40], 4);
    step!(H, d, a, b, c, 0, K[41], 11);
    step!(H, c, d, a, b, 3, K[42], 16);
    step!(H, b, c, d, a, 6, K[43], 23);
    step!(H, a, b, c, d, 9, K[44], 4);
    step!(H, d, a, b, c, 12, K[45], 11);
    step!(H, c, d, a, b, 15, K[46], 16);
    step!(H, b, c, d, a, 2, K[47], 23);

    step!(I, a, b, c, d, 0, K[48], 6);
    step!(I, d, a, b, c, 7, K[49], 10);
    step!(I, c, d, a, b, 14, K[50], 15);
    step!(I, b, c, d, a, 5, K[51], 21);
    step!(I, a, b, c, d, 12, K[52], 6);
    step!(I, d, a, b, c, 3, K[53], 10);
    step!(I, c, d, a, b, 10, K[54], 15);
    step!(I, b, c, d, a, 1, K[55], 21);
    step!(I, a, b, c, d, 8, K[56], 6);
    step!(I, d, a, b, c, 15, K[57], 10);
    step!(I, c, d, a, b, 6, K[58], 15);
    step!(I, b, c, d, a, 13, K[59], 21);
    step!(I, a, b, c, d, 4, K[60], 6);
    step!(I, d, a, b, c, 11, K[61], 10);
    step!(I, c, d, a, b, 2, K[62], 15);
    step!(I, b, c, d, a, 9, K[63], 21);

    state[0] = a0.wrapping_add(a);
    state[1] = b0.wrapping_add(b);
    state[2] = c0.wrapping_add(c);
    state[3] = d0.wrapping_add(d);
}

#[cfg(test)]
mod tests {
    //! Canonical-vector tests for the portable fallback.
    //!
    //! On `x86_64` and `aarch64` the public [`crate::transform`] dispatches to
    //! the assembly backend, so the crate-level RFC 1321 tests do *not*
    //! exercise this code on those hosts. The cross-check test
    //! `transform_matches_fallback_on_random_blocks` confirms structural
    //! equivalence between the active backend and the fallback, but it would
    //! not catch a shared bug — e.g. a wrong K constant copied into both
    //! tables. These tests close that gap by driving the fallback's
    //! `transform` directly through the RFC 1321 §A.5 vectors on every
    //! `cargo test` run, regardless of host architecture.
    use super::transform;
    use crate::{BLOCK_SIZE, DIGEST_LENGTH, IV, STATE_WORDS};

    /// Standalone one-shot MD5 built strictly on top of `fallback::transform`,
    /// independent of the public `Md5` type so this test can't be bypassed by
    /// a `cfg`-mistake in dispatch.
    fn fallback_md5(data: &[u8]) -> [u8; DIGEST_LENGTH] {
        let mut state: [u32; STATE_WORDS] = IV;
        let mut block = [0u8; BLOCK_SIZE];
        let mut chunks = data.chunks_exact(BLOCK_SIZE);
        for c in &mut chunks {
            block.copy_from_slice(c);
            transform(&mut state, &block);
        }
        let rem = chunks.remainder();
        // Final block(s): tail || 0x80 || zeros || 64-bit LE bit count.
        let bit_count = (data.len() as u64).wrapping_mul(8);
        block = [0u8; BLOCK_SIZE];
        block[..rem.len()].copy_from_slice(rem);
        block[rem.len()] = 0x80;
        if rem.len() >= 56 {
            transform(&mut state, &block);
            block = [0u8; BLOCK_SIZE];
        }
        block[56..].copy_from_slice(&bit_count.to_le_bytes());
        transform(&mut state, &block);

        let mut out = [0u8; DIGEST_LENGTH];
        for (i, w) in state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
        }
        out
    }

    fn hex(bytes: &[u8]) -> [u8; 32] {
        const H: &[u8; 16] = b"0123456789abcdef";
        let mut out = [0u8; 32];
        for (i, b) in bytes.iter().enumerate() {
            out[i * 2] = H[(b >> 4) as usize];
            out[i * 2 + 1] = H[(b & 0x0f) as usize];
        }
        out
    }

    // RFC 1321 §A.5 plus the standard "million a" vector.
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

    #[test]
    fn rfc1321_vectors_via_fallback() {
        for (input, want) in VECTORS {
            let got = fallback_md5(input);
            assert_eq!(
                core::str::from_utf8(&hex(&got)).unwrap(),
                *want,
                "fallback mismatch on input len {}",
                input.len()
            );
        }
    }

    #[test]
    fn fallback_million_a() {
        // RFC 1321 §A.5: MD5("a" * 1_000_000) = 7707d6ae4e027c70eea2a935c2296f21.
        // Drives the fallback through ~15_625 full block compressions.
        let data = [b'a'; 1_000_000];
        let got = fallback_md5(&data);
        assert_eq!(
            core::str::from_utf8(&hex(&got)).unwrap(),
            "7707d6ae4e027c70eea2a935c2296f21",
        );
    }
}
