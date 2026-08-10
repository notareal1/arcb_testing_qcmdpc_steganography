// matrix.rs -- ARCB v5.0
// Bit-sliced circulant matrix operations for QC-MDPC.
// M=16384, num_words = ceil(M/64) = 256. Each syndrome is O(weight * M/64).

use crate::parameters::{M, PUBKEY_BYTES};
use crate::polynomial::Polynomial;
use zeroize::Zeroize;

#[derive(Clone, Debug)]
pub struct Circulant {
    poly: Polynomial,
    /// Precomputed h as u64 words for bit-sliced syndrome.
    /// SECURITY: Contains secret key material — must be zeroized on drop.
    h_words: [u64; NUM_WORDS],
    row_weight: usize,
    /// Precomputed set bit positions (cached for decoder).
    /// SECURITY: Derived from secret key — must be zeroized on drop.
    ones: Vec<usize>,
}

impl Drop for Circulant {
    fn drop(&mut self) {
        self.h_words.zeroize();
        self.ones.zeroize();
        // self.poly is zeroized by Polynomial::drop
    }
}

/// Number of u64 words needed for M-bit polynomial = ceil(M/64).
pub const NUM_WORDS: usize = (M + 63) / 64; // 256 for M=16384

impl Circulant {
    pub fn new(poly: Polynomial) -> Self {
        let w = poly.weight();
        let ones = Self::get_set_bits(&poly);
        let h_words = bytes_to_words(poly.as_bytes());

        Circulant {
            poly,
            h_words,
            row_weight: w,
            ones,
        }
    }

    pub fn polynomial(&self) -> &Polynomial {
        &self.poly
    }

    pub fn row_weight(&self) -> usize {
        self.row_weight
    }

    /// Return the precomputed set bit positions.
    pub fn ones(&self) -> &[usize] {
        &self.ones
    }

    /// Constant-time syndrome computation.
    ///
    /// For each bit position `pos` in [0, M), conditionally XOR a cyclically-
    /// shifted copy of h_words into result_words. The shift amount depends on
    /// `pos` (a public loop counter), and the condition depends on `bit_val`
    /// (the secret input bit).
    ///
    /// SECURITY: `s0`/`s1` indices depend only on public `pos` and loop `i`,
    /// so the cache access pattern reveals nothing about the secret input.
    /// The secret is protected by `do_xor` which is 0 when `bit_val=0`.
    /// `read_volatile` prevents the compiler from optimizing away the reads
    /// when `do_xor` happens to be 0.
    ///
    /// Complexity: O(PUBKEY_BYTES * 8 * NUM_WORDS)
    pub fn compute_syndrome_ct(&self, vec: &Polynomial) -> Polynomial {
        let num_words = NUM_WORDS;
        let h_words = self.h_words;
        let mut result_words = [0u64; NUM_WORDS];
        let bytes = vec.as_bytes();

        for byte_idx in 0..PUBKEY_BYTES {
            let byte = bytes[byte_idx];
            for bit in 0..8 {
                let pos = byte_idx * 8 + bit;
                let bit_val = ((byte >> bit) & 1) as u64;
                let in_range = ((pos < M) as u64).wrapping_neg();
                let do_xor = in_range & bit_val.wrapping_neg();

                let word_shift = pos >> 6;
                let bit_shift = pos & 63;

                // CT shift mask: !0 when bit_shift==0, 0 otherwise
                let shift_mask = ((bit_shift as u64).wrapping_sub(1) >> 63).wrapping_neg();
                let shift_right = (64 - bit_shift) & 63;

                for i in 0..num_words {
                    let s0 = (i + num_words - word_shift) % num_words;
                    let s1 = (i + num_words - word_shift - 1) % num_words;
                    // Volatile reads: prevent compiler from optimizing away
                    // the load when do_xor is 0 (secret bit is 0).
                    let v0 = unsafe { core::ptr::read_volatile(&h_words[s0]) };
                    let v1 = unsafe { core::ptr::read_volatile(&h_words[s1]) };

                    let shifted = (v0.wrapping_shl(bit_shift as u32)
                        | v1.wrapping_shr(shift_right as u32))
                        & !shift_mask;
                    let no_shift = v0 & shift_mask;
                    // Use black_box to prevent compiler from proving do_xor==0
                    // and skipping the XOR entirely.
                    let mask = core::hint::black_box(do_xor);
                    result_words[i] ^= (no_shift | shifted) & mask;
                }
            }
        }

        Polynomial::from_bytes(&words_to_bytes(&result_words))
    }

    /// Fast syndrome: s = H * v (non-constant-time).
    /// WARNING: This function uses early-skip on zero bytes/bits, which leaks
    /// information about the input through timing/cache side channels.
    /// ONLY use this on PUBLIC data (public keys, test vectors, random errors).
    /// NEVER use on secret key material or decapsulation inputs.
    pub fn compute_syndrome(&self, vec: &Polynomial) -> Polynomial {
        let num_words = NUM_WORDS;
        let h_words = self.h_words;
        let mut result_words = [0u64; NUM_WORDS];

        for byte_idx in 0..PUBKEY_BYTES {
            let byte = vec.as_bytes()[byte_idx];
            if byte == 0 {
                continue;
            }
            for bit in 0..8 {
                let pos = byte_idx * 8 + bit;
                if pos >= M {
                    break;
                }
                if (byte >> bit) & 1 == 0 {
                    continue;
                }
                let word_shift = pos / 64;
                let bit_shift = pos % 64;
                if bit_shift == 0 {
                    for i in 0..num_words {
                        let src = (i + num_words - word_shift) % num_words;
                        result_words[i] ^= h_words[src];
                    }
                } else {
                    for i in 0..num_words {
                        let s0 = (i + num_words - word_shift) % num_words;
                        let s1 = (i + num_words - word_shift - 1) % num_words;
                        // CT: volatile read to prevent optimization
                        let v0 = unsafe { core::ptr::read_volatile(&h_words[s0]) };
                        let v1 = unsafe { core::ptr::read_volatile(&h_words[s1]) };
                        result_words[i] ^= (v0 << bit_shift) | (v1 >> (64 - bit_shift));
                    }
                }
            }
        }

        Polynomial::from_bytes(&words_to_bytes(&result_words))
    }

    fn get_set_bits(poly: &Polynomial) -> Vec<usize> {
        let mut positions = Vec::new();
        for byte_idx in 0..PUBKEY_BYTES {
            let byte = poly.as_bytes()[byte_idx];
            if byte == 0 {
                continue;
            }
            for bit in 0..8 {
                let p = byte_idx * 8 + bit;
                if p >= M {
                    break;
                }
                if (byte >> bit) & 1 == 1 {
                    positions.push(p);
                }
            }
        }
        positions
    }
}

// -- Bit-sliced helpers ------------------------------------------------

pub fn bytes_to_words(bytes: &[u8; PUBKEY_BYTES]) -> [u64; NUM_WORDS] {
    let mut words = [0u64; NUM_WORDS];
    for i in 0..NUM_WORDS {
        let off = i * 8;
        // Handle last word which may have fewer than 8 bytes
        let mut buf = [0u8; 8];
        let remaining = PUBKEY_BYTES.saturating_sub(off);
        let to_copy = remaining.min(8);
        if to_copy > 0 {
            buf[..to_copy].copy_from_slice(&bytes[off..off + to_copy]);
        }
        words[i] = u64::from_le_bytes(buf);
    }
    words
}

fn words_to_bytes(words: &[u64; NUM_WORDS]) -> [u8; PUBKEY_BYTES] {
    let mut bytes = [0u8; PUBKEY_BYTES];
    for (i, &w) in words.iter().enumerate() {
        let off = i * 8;
        if off >= PUBKEY_BYTES {
            break;
        }
        let le = w.to_le_bytes();
        let to_copy = (PUBKEY_BYTES - off).min(8);
        bytes[off..off + to_copy].copy_from_slice(&le[..to_copy]);
    }
    bytes
}

// -- Tests ------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_syndrome_matches_poly_mul() {
        let mut rng = rand::thread_rng();
        let h = Polynomial::random_with_weight(&mut rng, 45);
        let v = Polynomial::random_with_weight(&mut rng, 25);
        let circ = Circulant::new(h.clone());
        let syndrome = circ.compute_syndrome(&v);
        let reference = h.multiply(&v);
        assert!(syndrome.equals(&reference));
    }

    #[test]
    fn test_syndrome_zero_vector() {
        let mut rng = rand::thread_rng();
        let h = Polynomial::random_with_weight(&mut rng, 45);
        let circ = Circulant::new(h);
        let s = circ.compute_syndrome(&Polynomial::zero());
        assert!(s.is_zero());
    }

    #[test]
    fn test_syndrome_single_bit() {
        let mut rng = rand::thread_rng();
        let h = Polynomial::random_with_weight(&mut rng, 45);
        let mut v = Polynomial::zero();
        v.set_bit(0, 1);
        let circ = Circulant::new(h.clone());
        let s = circ.compute_syndrome(&v);
        assert!(s.equals(&h), "syndrome of e_0 should equal h");
    }

    #[test]
    fn test_syndrome_two_bits() {
        let mut h = Polynomial::zero();
        h.set_bit(0, 1);
        h.set_bit(1, 1);
        let circ = Circulant::new(h.clone());

        let mut v = Polynomial::zero();
        v.set_bit(0, 1);
        v.set_bit(1, 1);

        let syndrome = circ.compute_syndrome(&v);
        let reference = h.multiply(&v);
        assert!(syndrome.equals(&reference), "two-bit syndrome mismatch");
    }

    #[test]
    fn test_syndrome_cross_word_boundary() {
        let mut h = Polynomial::zero();
        h.set_bit(0, 1);
        let circ = Circulant::new(h.clone());

        let mut v = Polynomial::zero();
        v.set_bit(64, 1);

        let syndrome = circ.compute_syndrome(&v);
        let reference = h.multiply(&v);
        assert!(syndrome.equals(&reference), "bit-64 syndrome mismatch");

        let mut v = Polynomial::zero();
        v.set_bit(65, 1);

        let syndrome = circ.compute_syndrome(&v);
        let reference = h.multiply(&v);
        assert!(syndrome.equals(&reference), "bit-65 syndrome mismatch");
    }

    #[test]
    fn test_syndrome_ct_matches_non_ct() {
        let mut rng = rand::thread_rng();
        let h = Polynomial::random_with_weight(&mut rng, 45);
        let v = Polynomial::random_with_weight(&mut rng, 25);
        let circ = Circulant::new(h);
        let s_fast = circ.compute_syndrome(&v);
        let s_ct = circ.compute_syndrome_ct(&v);
        assert!(
            s_fast.equals(&s_ct),
            "Bitsliced and non-CT syndrome should match"
        );
    }

    #[test]
    fn test_bitsliced_matches_non_ct() {
        let mut rng = rand::thread_rng();
        let h = Polynomial::random_with_weight(&mut rng, 45);
        let v = Polynomial::random_with_weight(&mut rng, 25);
        let circ = Circulant::new(h);
        let s_fast = circ.compute_syndrome(&v);
        let s_bitsliced = circ.compute_syndrome_ct(&v);
        assert!(
            s_fast.equals(&s_bitsliced),
            "Bitsliced and non-CT syndrome should match. Fast weight: {}, Bitsliced weight: {}",
            s_fast.weight(),
            s_bitsliced.weight()
        );
    }
}
