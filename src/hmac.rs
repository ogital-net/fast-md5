//! HMAC-MD5 (RFC 2104) — streaming.
//!
//! Used by RADIUS Message-Authenticator (RFC 3579 §3.2), CHAP, and
//! various legacy SASL/SIP digests. As with raw MD5, HMAC-MD5 is
//! **not safe** for new cryptographic designs: collisions in the
//! underlying hash translate into existential forgeries on HMAC under
//! related-key attacks, and the construction has known weaknesses
//! against differential cryptanalysis on reduced rounds. This crate
//! exposes it solely to support legacy protocols.
//!
//! ## Performance notes
//!
//! [`HmacMd5::new`] performs the key-derivation work eagerly and
//! caches **only** the post-ipad and post-opad MD5 states (two
//! `[u32; 4]` words = 32 bytes total). Subsequent
//! [`update`](HmacMd5::update) calls are pure delegation to the inner
//! `Md5`, and [`finalize`](HmacMd5::finalize) costs exactly one extra
//! 64-byte compression on top of the inner `finalize`. This matches
//! the structure used by AWS-LC's `HMAC_CTX` and avoids the redundant
//! ipad/opad re-XOR + re-compression that a literal RFC 2104
//! implementation would do per finalize.

use crate::{transform, Md5, BLOCK_SIZE, DIGEST_LENGTH, IV, STATE_WORDS};

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

/// Streaming HMAC-MD5 (RFC 2104).
///
/// ```
/// use fast_md5::HmacMd5;
///
/// let mut h = HmacMd5::new(b"Jefe");
/// h.update(b"what do ya want ");
/// h.update(b"for nothing?");
/// assert_eq!(
///     h.finalize(),
///     [
///         0x75, 0x0c, 0x78, 0x3e, 0x6a, 0xb0, 0xb5, 0x03,
///         0xea, 0xa8, 0x6e, 0x31, 0x0a, 0x5d, 0xb7, 0x38,
///     ],
/// );
/// ```
pub struct HmacMd5 {
    /// Inner `Md5` whose state has already absorbed `ipad ^ K` and
    /// whose `count` is preset to one block. All subsequent
    /// [`update`](Self::update) calls feed straight in.
    inner: Md5,
    /// MD5 state after compressing `opad ^ K`. Used in
    /// [`finalize`](Self::finalize) to seed the outer hash without
    /// re-running the opad block.
    outer_state: [u32; STATE_WORDS],
}

impl HmacMd5 {
    /// Construct a new HMAC-MD5 keyed with `key`.
    ///
    /// Per RFC 2104, keys longer than the block size are first reduced
    /// via MD5; shorter keys are zero-padded to the block size.
    #[inline]
    pub fn new(key: &[u8]) -> Self {
        // Step 1: derive the 64-byte key block `k_block`.
        //   - len <= 64  : zero-pad
        //   - len  > 64  : MD5(key) || zeros
        let mut k_block = [0u8; BLOCK_SIZE];
        if key.len() > BLOCK_SIZE {
            let h = crate::digest(key);
            k_block[..DIGEST_LENGTH].copy_from_slice(&h);
        } else {
            k_block[..key.len()].copy_from_slice(key);
        }

        // Step 2: build ipad and opad blocks in one pass.
        let mut ipad_block = [0u8; BLOCK_SIZE];
        let mut opad_block = [0u8; BLOCK_SIZE];
        for i in 0..BLOCK_SIZE {
            ipad_block[i] = k_block[i] ^ IPAD;
            opad_block[i] = k_block[i] ^ OPAD;
        }

        // Step 3: precompute MD5 state after the ipad/opad blocks.
        // After this we never need the key (or its derivatives) again.
        let mut inner_state = IV;
        transform(&mut inner_state, &ipad_block);
        let mut outer_state = IV;
        transform(&mut outer_state, &opad_block);

        Self {
            inner: Md5::from_parts(inner_state, BLOCK_SIZE as u64),
            outer_state,
        }
    }

    /// Absorb additional message bytes.
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Consume the HMAC and return the 16-byte authentication tag.
    #[inline]
    pub fn finalize(self) -> [u8; DIGEST_LENGTH] {
        // Inner: finishes hashing  ipad_block || message.
        let inner_digest = self.inner.finalize();

        // Outer: opad_block || inner_digest, with state seeded so the
        // opad block is implicit.
        let mut outer = Md5::from_parts(self.outer_state, BLOCK_SIZE as u64);
        outer.update(&inner_digest);
        outer.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> [u8; 32] {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = [0u8; 32];
        for (i, b) in bytes.iter().enumerate() {
            out[i * 2] = HEX[(b >> 4) as usize];
            out[i * 2 + 1] = HEX[(b & 0x0f) as usize];
        }
        out
    }

    fn mac(key: &[u8], msg: &[u8]) -> [u8; DIGEST_LENGTH] {
        let mut h = HmacMd5::new(key);
        h.update(msg);
        h.finalize()
    }

    // RFC 2202 §2 test vectors for HMAC-MD5.
    #[test]
    fn rfc2202_test_case_1() {
        let key = [0x0bu8; 16];
        let want = "9294727a3638bb1c13f48ef8158bfc9d";
        let got = mac(&key, b"Hi There");
        assert_eq!(core::str::from_utf8(&hex(&got)).unwrap(), want);
    }

    #[test]
    fn rfc2202_test_case_2() {
        let want = "750c783e6ab0b503eaa86e310a5db738";
        let got = mac(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(core::str::from_utf8(&hex(&got)).unwrap(), want);
    }

    #[test]
    fn rfc2202_test_case_3() {
        let key = [0xaau8; 16];
        let data = [0xddu8; 50];
        let want = "56be34521d144c88dbb8c733f0e8b3f6";
        let got = mac(&key, &data);
        assert_eq!(core::str::from_utf8(&hex(&got)).unwrap(), want);
    }

    #[test]
    fn rfc2202_test_case_4() {
        let key: [u8; 25] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
        ];
        let data = [0xcdu8; 50];
        let want = "697eaf0aca3a3aea3a75164746ffaa79";
        let got = mac(&key, &data);
        assert_eq!(core::str::from_utf8(&hex(&got)).unwrap(), want);
    }

    #[test]
    fn rfc2202_test_case_5() {
        let key = [0x0cu8; 16];
        let want = "56461ef2342edc00f9bab995690efd4c";
        let got = mac(&key, b"Test With Truncation");
        assert_eq!(core::str::from_utf8(&hex(&got)).unwrap(), want);
    }

    // Long-key path: key longer than BLOCK_SIZE forces the MD5(key) reduction.
    #[test]
    fn rfc2202_test_case_6_long_key() {
        let key = [0xaau8; 80];
        let want = "6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd";
        let got = mac(
            &key,
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(core::str::from_utf8(&hex(&got)).unwrap(), want);
    }

    #[test]
    fn rfc2202_test_case_7_long_key_and_data() {
        let key = [0xaau8; 80];
        let want = "6f630fad67cda0ee1fb1f562db3aa53e";
        let got = mac(
            &key,
            b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
        );
        assert_eq!(core::str::from_utf8(&hex(&got)).unwrap(), want);
    }

    // Boundary: key exactly BLOCK_SIZE bytes — neither truncated nor padded.
    #[test]
    fn key_exactly_one_block() {
        let key = [0x42u8; BLOCK_SIZE];
        let direct = mac(&key, b"abc");
        // Cross-check via the streaming API split across update calls.
        let mut h = HmacMd5::new(&key);
        h.update(b"a");
        h.update(b"b");
        h.update(b"c");
        let streamed = h.finalize();
        assert_eq!(direct, streamed);
    }

    // Streaming must equal one-shot for a multi-block message.
    #[test]
    fn streaming_matches_oneshot_multiblock() {
        let key = b"radius shared secret";
        let mut data = [0u8; 1000];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(0x9b).wrapping_add(0x37);
        }
        let oneshot = mac(key, &data);
        let mut h = HmacMd5::new(key);
        for chunk in data.chunks(13) {
            h.update(chunk);
        }
        assert_eq!(h.finalize(), oneshot);
    }

    // Empty key and empty message — degenerate but legal.
    #[test]
    fn empty_key_and_message() {
        // Computed via openssl: `printf '' | openssl dgst -md5 -hmac ''`
        let want = "74e6f7298a9c2d168935f58c001bad88";
        let got = mac(b"", b"");
        assert_eq!(core::str::from_utf8(&hex(&got)).unwrap(), want);
    }
}
