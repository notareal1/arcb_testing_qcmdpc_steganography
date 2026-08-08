// polynomial.rs -- ARCB v5.0 (Production)
// Polynomials over GF(2)[x]/(x^M - 1).
// Packed representation: PUBKEY_BYTES bytes, bit 0 of byte 0 = coeff of x^0.

use crate::error::{ArcError, ArcResult};
use crate::parameters::{M, PUBKEY_BYTES};
use rand::Rng;
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Polynomial {
    data: [u8; PUBKEY_BYTES],
}

impl Drop for Polynomial {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl Polynomial {
    pub fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl Polynomial {
    pub fn zero() -> Polynomial {
        Polynomial { data: [0u8; PUBKEY_BYTES] }
    }

    pub fn from_positions(positions: &[usize]) -> Polynomial {
        let mut poly = Polynomial::zero();
        for &pos in positions {
            poly.set_bit(pos, 1);
        }
        poly
    }

    pub fn from_bits(bits: &[u8]) -> ArcResult<Self> {
        if bits.len() != M {
            return Err(ArcError::InvalidInput(format!("expected {} bits, got {}", M, bits.len())));
        }
        let mut poly = Polynomial::zero();
        for (i, &b) in bits.iter().enumerate() {
            if b == 1 {
                poly.set_bit(i, 1);
            } else if b != 0 {
                return Err(ArcError::InvalidInput(format!("bit {} is {} (must be 0 or 1)", i, b)));
            }
        }
        Ok(poly)
    }

    pub fn random_with_weight<R: Rng>(rng: &mut R, weight: usize) -> Polynomial {
        let mut positions: Vec<usize> = (0..M).collect();
        for i in 0..weight {
            let j = rng.gen_range(i..M);
            positions.swap(i, j);
        }
        Self::from_positions(&positions[..weight])
    }

    pub fn random_full<R: Rng>(rng: &mut R) -> Polynomial {
        let mut poly = Polynomial::zero();
        rng.fill_bytes(&mut poly.data);
        let remainder = M % 8;
        if remainder != 0 {
            poly.data[PUBKEY_BYTES - 1] &= (1u8 << remainder) - 1;
        }
        poly
    }

    #[inline]
    pub fn get_bit(&self, index: usize) -> u8 {
        debug_assert!(index < M);
        (self.data[index / 8] >> (index % 8)) & 1
    }

    #[inline]
    pub fn set_bit(&mut self, index: usize, value: u8) {
        debug_assert!(index < M);
        let mask = 1u8 << (index % 8);
        let byte = &mut self.data[index / 8];
        *byte = (*byte & !mask) | ((value & 1) << (index % 8));
    }

    #[inline]
    pub fn flip_bit(&mut self, index: usize) {
        debug_assert!(index < M);
        self.data[index / 8] ^= 1 << (index % 8);
    }

    #[inline]
    pub fn flip_bit_ct(&mut self, index: usize, mask: u8) {
        debug_assert!(index < M);
        self.data[index / 8] ^= mask << (index % 8);
    }

    #[inline]
    pub fn weight(&self) -> usize {
        // Use hardware popcnt — constant-time on all modern x86/x64 CPUs.
        // On ARM, this compiles to `cnt` instruction which is also CT.
        // Avoids lookup table which would leak cache access pattern.
        self.data.iter().map(|&b| b.count_ones() as usize).sum()
    }

    pub fn is_zero(&self) -> bool {
        self.data.iter().all(|&b| b == 0)
    }

    pub fn equals(&self, other: &Self) -> bool {
        self.data == other.data
    }

    pub fn ct_bytes_equal(&self, other: &Self) -> bool {
        self.data.ct_eq(&other.data).into()
    }

    pub fn as_bytes(&self) -> &[u8; PUBKEY_BYTES] {
        &self.data
    }

    pub fn as_bytes_mut(&mut self) -> &mut [u8; PUBKEY_BYTES] {
        &mut self.data
    }

    pub fn from_bytes(bytes: &[u8; PUBKEY_BYTES]) -> Polynomial {
        let mut poly = Polynomial { data: *bytes };
        let remainder = M % 8;
        if remainder != 0 {
            poly.data[PUBKEY_BYTES - 1] &= (1u8 << remainder) - 1;
        }
        poly
    }

    pub fn add(&self, other: &Self) -> Polynomial {
        let mut result = Polynomial::zero();
        for (i, (a, b)) in self.data.iter().zip(other.data.iter()).enumerate() {
            result.data[i] = a ^ b;
        }
        result
    }

    pub fn xor(&self, other: &Self) -> Polynomial {
        self.add(other)
    }

    /// Multiply in R = GF(2)[x]/(x^M - 1) — constant-time version.
    pub fn multiply_ct(&self, other: &Self) -> Polynomial {
        let mut result = Polynomial::zero();
        let bytes = self.as_bytes();
        for byte_idx in 0..PUBKEY_BYTES {
            let byte = bytes[byte_idx];
            for bit in 0..8 {
                let pos = byte_idx * 8 + bit;
                let in_range = ((pos < M) as u64).wrapping_neg();
                let bit_val = ((byte >> bit) & 1) as u64;
                let mask = in_range & bit_val.wrapping_neg();
                let shifted = cyclic_shift_bytes_ct(other.as_bytes(), pos);
                for i in 0..PUBKEY_BYTES {
                    result.data[i] ^= shifted[i] & (mask as u8);
                }
            }
        }
        result
    }

    /// Multiply in R = GF(2)[x]/(x^M - 1) — fast non-constant-time version.
    pub fn multiply(&self, other: &Self) -> Polynomial {
        let (a, b) = if self.weight() <= other.weight() {
            (self, other)
        } else {
            (other, self)
        };
        let mut result = Polynomial::zero();
        for pos in a.positions_of_ones() {
            let shifted = cyclic_shift_bytes(b.as_bytes(), pos);
            for i in 0..PUBKEY_BYTES {
                result.data[i] ^= shifted[i];
            }
        }
        result
    }

    pub fn positions_of_ones(&self) -> Vec<usize> {
        let mut pos = Vec::with_capacity(self.weight());
        for byte_idx in 0..PUBKEY_BYTES {
            let byte = self.data[byte_idx];
            if byte == 0 { continue; }
            for bit in 0..8 {
                let p = byte_idx * 8 + bit;
                if p >= M { break; }
                if (byte >> bit) & 1 == 1 {
                    pos.push(p);
                }
            }
        }
        pos
    }

    pub fn cyclic_shift(&self, shift: usize) -> Polynomial {
        let shift_mod = shift % M;
        if shift_mod == 0 { return self.clone(); }
        let result = cyclic_shift_bytes(&self.data, shift_mod);
        Polynomial { data: result }
    }
    /// Inversion in R = GF(2)[x]/(x^M - 1) via extended Euclidean algorithm.
    /// NOTE: Not constant-time, but only called during key generation (not in decapsulation hot path).
    /// For production, consider using a constant-time GCD implementation.
    pub fn invert(&self) -> Option<Self> {
        let a = self.to_bit_vec();
        let mut f = vec![0u8; M + 1];
        f[0] = 1;
        f[M] = 1;
        let (gcd, u, _v) = ext_gcd_poly(&a, &f);
        if !(gcd.len() == 1 && gcd[0] == 1) { return None; }
        let inv = reduce_mod_l_final(&u, M);
        Some(inv)
    }

    fn to_bit_vec(&self) -> Vec<u8> {
        let mut v = vec![0u8; M];
        for i in 0..M { v[i] = self.get_bit(i); }
        v
    }

    fn from_bit_vec_truncated(bits: &[u8]) -> Polynomial {
        let mut poly = Polynomial::zero();
        for (i, &b) in bits.iter().enumerate() {
            if i >= M { break; }
            if b == 1 { poly.set_bit(i, 1); }
        }
        poly
    }
}

/// Cyclic shift of byte array by `shift` bits to the left.
/// CT version: scan-all pattern, no secret-dependent index.
fn cyclic_shift_bytes_ct(bytes: &[u8; PUBKEY_BYTES], shift: usize) -> [u8; PUBKEY_BYTES] {
    let byte_shift = shift / 8;
    let bit_shift = shift % 8;
    let mut result = [0u8; PUBKEY_BYTES];
    let bit_shift_u32 = bit_shift as u32;

    for i in 0..PUBKEY_BYTES {
        let s0_target = (i + PUBKEY_BYTES - byte_shift) % PUBKEY_BYTES;
        let s1_target = (i + PUBKEY_BYTES - byte_shift - 1) % PUBKEY_BYTES;

        // CT gather: scan all bytes, select s0 and s1 using bitwise equality
        let mut v0 = 0u8;
        let mut v1 = 0u8;
        for j in 0..PUBKEY_BYTES {
            // Bitwise equality: 1 if j == target, 0 otherwise
            let diff0 = (j as u16 ^ s0_target as u16).wrapping_sub(1);
            let diff1 = (j as u16 ^ s1_target as u16).wrapping_sub(1);
            let m0 = ((diff0 >> 15) as u8).wrapping_neg(); // 0xFF if j==s0, else 0
            let m1 = ((diff1 >> 15) as u8).wrapping_neg(); // 0xFF if j==s1, else 0
            v0 |= bytes[j] & m0;
            v1 |= bytes[j] & m1;
        }

        let combined = ((v0 as u16) << 8) | (v1 as u16);
        result[i] = (combined << bit_shift_u32 >> 8) as u8;
    }

    let remainder = M % 8;
    if remainder != 0 {
        result[PUBKEY_BYTES - 1] &= (1u8 << remainder) - 1;
    }
    result
}

/// Cyclic shift of byte array by `shift` bits to the left.
/// Non-CT version for fast path.
fn cyclic_shift_bytes(bytes: &[u8; PUBKEY_BYTES], shift: usize) -> [u8; PUBKEY_BYTES] {
    let byte_shift = shift / 8;
    let bit_shift = shift % 8;
    let mut result = [0u8; PUBKEY_BYTES];
    let bit_shift_u32 = bit_shift as u32;

    for i in 0..PUBKEY_BYTES {
        let s0 = (i + PUBKEY_BYTES - byte_shift) % PUBKEY_BYTES;
        let s1 = (i + PUBKEY_BYTES - byte_shift - 1) % PUBKEY_BYTES;
        let combined = ((bytes[s0] as u16) << 8) | (bytes[s1] as u16);
        result[i] = (combined << bit_shift_u32 >> 8) as u8;
    }

    let remainder = M % 8;
    if remainder != 0 {
        result[PUBKEY_BYTES - 1] &= (1u8 << remainder) - 1;
    }
    result
}

fn ext_gcd_poly(a: &[u8], b: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut r0 = a.to_vec();
    let mut r1 = b.to_vec();
    let mut s0 = vec![1u8];
    let mut s1 = vec![0u8];
    let mut t0 = vec![0u8];
    let mut t1 = vec![1u8];

    while !is_zero_poly(&r1) {
        let (q, r) = poly_div(&r0, &r1);
        let q_s1 = poly_mul(&q, &s1);
        let new_s = poly_add(&s0, &q_s1);
        let q_t1 = poly_mul(&q, &t1);
        let new_t = poly_add(&t0, &q_t1);
        r0 = r1; r1 = r; s0 = s1; s1 = new_s; t0 = t1; t1 = new_t;
    }
    (r0, s0, t0)
}

fn reduce_mod_l_final(poly: &[u8], modulus_deg: usize) -> Polynomial {
    let mut coeffs = poly.to_vec();
    for d in (modulus_deg..coeffs.len()).rev() {
        if coeffs[d] == 1 {
            coeffs[d % modulus_deg] ^= 1;
            coeffs[d] = 0;
        }
    }
    coeffs.resize(modulus_deg, 0);
    Polynomial::from_bit_vec_truncated(&coeffs)
}

fn poly_div(a: &[u8], b: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let a = trim(a);
    let b = trim(b);
    if b.is_empty() || (b.len() == 1 && b[0] == 0) {
        panic!("Division by zero polynomial");
    }
    let b_deg = b.len() - 1;
    let mut r = a;
    let max_q = if r.len() > b_deg { r.len() - b_deg } else { 0 };
    let mut q = vec![0u8; max_q];
    while r.len() > b_deg && !(r.len() == 1 && r[0] == 0) {
        let r_deg = r.len() - 1;
        let shift = r_deg - b_deg;
        q[shift] = 1;
        for j in 0..b.len() { r[shift + j] ^= b[j]; }
        while r.last() == Some(&0) { r.pop(); }
    }
    if r.is_empty() { r = vec![0u8]; }
    (trim(&q), trim(&r))
}

fn poly_mul(a: &[u8], b: &[u8]) -> Vec<u8> {
    let a = trim(a);
    let b = trim(b);
    if a.is_empty() || b.is_empty() || (a.len() == 1 && a[0] == 0) || (b.len() == 1 && b[0] == 0) {
        return vec![0u8];
    }
    let mut res = vec![0u8; a.len() + b.len() - 1];
    for i in 0..a.len() {
        if a[i] == 1 {
            for j in 0..b.len() {
                if b[j] == 1 { res[i + j] ^= 1; }
            }
        }
    }
    trim(&res)
}

fn poly_add(a: &[u8], b: &[u8]) -> Vec<u8> {
    let max_len = std::cmp::max(a.len(), b.len());
    let mut res = vec![0u8; max_len];
    for i in 0..a.len() { res[i] ^= a[i]; }
    for i in 0..b.len() { res[i] ^= b[i]; }
    trim(&res)
}

fn is_zero_poly(p: &[u8]) -> bool {
    p.iter().all(|&b| b == 0)
}

fn trim(p: &[u8]) -> Vec<u8> {
    let mut end = p.len();
    while end > 0 && p[end - 1] == 0 { end -= 1; }
    if end == 0 { vec![0u8] } else { p[..end].to_vec() }
}

#[cfg(test)]
mod tests {
    use rand::Rng;
    use super::*;
    use crate::parameters::*;

    #[test]
    fn test_zero_and_bit_ops() {
        let mut p = Polynomial::zero();
        assert!(p.is_zero());
        assert_eq!(p.weight(), 0);
        p.set_bit(0, 1);
        assert_eq!(p.get_bit(0), 1);
        assert_eq!(p.weight(), 1);
        p.flip_bit(0);
        assert_eq!(p.get_bit(0), 0);
        assert!(p.is_zero());
    }

    #[test]
    fn test_add_xor() {
        let mut a = Polynomial::zero();
        a.set_bit(0, 1);
        a.set_bit(10, 1);
        let mut b = Polynomial::zero();
        b.set_bit(10, 1);
        b.set_bit(100, 1);
        let c = a.add(&b);
        assert_eq!(c.weight(), 2);
        assert_eq!(c.get_bit(0), 1);
        assert_eq!(c.get_bit(10), 0);
        assert_eq!(c.get_bit(100), 1);
    }

    #[test]
    fn test_cyclic_shift() {
        let mut a = Polynomial::zero();
        a.set_bit(0, 1);
        a.set_bit(M - 1, 1);
        let s = a.cyclic_shift(1);
        assert_eq!(s.get_bit(1), 1);
        assert_eq!(s.get_bit(0), 1); // wrap-around
        assert_eq!(s.get_bit(M - 1), 0);
    }

    #[test]
    fn test_multiply_basic() {
        let mut a = Polynomial::zero();
        a.set_bit(0, 1);
        a.set_bit(1, 1);
        let prod = a.multiply(&a);
        assert_eq!(prod.get_bit(0), 1);
        assert_eq!(prod.get_bit(1), 0);
        assert_eq!(prod.get_bit(2), 1);
    }

    #[test]
    fn test_multiply_with_weight() {
        let mut rng = rand::thread_rng();
        let p = Polynomial::random_with_weight(&mut rng, ROW_WEIGHT);
        let q = Polynomial::random_with_weight(&mut rng, ROW_WEIGHT);
        let _prod = p.multiply(&q);
    }

    #[test]
    fn test_random_weight_exact() {
        let mut rng = rand::thread_rng();
        for _ in 0..20 {
            let p = Polynomial::random_with_weight(&mut rng, ROW_WEIGHT);
            assert_eq!(p.weight(), ROW_WEIGHT);
        }
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut rng = rand::thread_rng();
        let p = Polynomial::random_full(&mut rng);
        let bytes = *p.as_bytes();
        let q = Polynomial::from_bytes(&bytes);
        assert!(p.equals(&q));
    }

    #[test]
    fn test_invert_known() {
        let mut one = Polynomial::zero();
        one.set_bit(0, 1);
        let inv = one.invert().unwrap();
        assert!(one.equals(&inv));
    }

    #[test]
    fn test_invert_zero() {
        let z = Polynomial::zero();
        assert!(z.invert().is_none());
    }
}

