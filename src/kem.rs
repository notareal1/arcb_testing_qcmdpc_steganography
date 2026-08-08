// kem.rs -- ARCB v5.0 (Production)
// QC-MDPC Niederreiter KEM with Steganographic Encoding.
//
// KeyGen: h0, h1 (secret), p = h0^{-1} * h1 (public)
// Encapsulate: random e → s = e0 + e1*p → K = BLAKE3(e0||e1)
// Decapsulate: s → s' = h0*s = H*e → decode e → K = BLAKE3(e0||e1)
//
// IND-CCA2 via implicit rejection (BIKE-style):
//   If decode fails or re-encryption mismatch, return H(seed, ct) instead of error.
//   Fully branchless: decode returns (e0, e1, converged), no match/unwrap on secret.

use crate::decoder::decode;
use crate::error::ArcError;
use crate::matrix::Circulant;
use crate::parameters::*;
use crate::polynomial::Polynomial;
use crate::utils;
use blake3;
use rand::rngs::OsRng;
use rand::Rng;

#[derive(Clone)]
pub struct KemCiphertext {
    pub syndrome: [u8; SYNDROME_BYTES],
}

/// Encapsulate: produce (ciphertext, session_key) from public key.
pub fn encapsulate(public_key: &Polynomial) -> (KemCiphertext, [u8; SESSION_KEY_BYTES]) {
    let (e0, e1) = generate_error();

    // Use multiply_ct for secret error vector e1
    let e1p = e1.multiply_ct(public_key);
    let syndrome_poly = e0.add(&e1p);

    let mut syndrome = [0u8; SYNDROME_BYTES];
    syndrome.copy_from_slice(syndrome_poly.as_bytes());

    let e_bytes = [e0.as_bytes().as_slice(), e1.as_bytes().as_slice()].concat();
    let mut key_input = Vec::with_capacity(16 + e_bytes.len());
    key_input.extend_from_slice(b"ARCB-KEM-KEY-V1");
    key_input.extend_from_slice(&e_bytes);
    let key: [u8; SESSION_KEY_BYTES] = blake3::hash(&key_input).into();

    (KemCiphertext { syndrome }, key)
}

/// Derive a deterministic rejection key from seed and ciphertext.
fn rejection_key(seed: &[u8; SEED_BYTES], ct: &KemCiphertext) -> [u8; SESSION_KEY_BYTES] {
    let mut input = Vec::with_capacity(16 + SEED_BYTES + SYNDROME_BYTES);
    input.extend_from_slice(b"ARCB-KEM-REJ-V1");
    input.extend_from_slice(seed);
    input.extend_from_slice(&ct.syndrome);
    blake3::hash(&input).into()
}

/// Decapsulate: recover session key from ciphertext using secret seed.
/// IND-CCA2: implicit rejection on failure. Fully branchless.
pub fn decapsulate(
    seed: &[u8; SEED_BYTES],
    ct: &KemCiphertext,
) -> Result<[u8; SESSION_KEY_BYTES], ArcError> {
    let (h0_poly, h1_poly) = utils::derive_secret_polynomials(seed)?;
    let h0 = Circulant::new(h0_poly);
    let h1 = Circulant::new(h1_poly);
    decapsulate_with_polys(seed, &h0, &h1, ct)
}

/// Decapsulate with precomputed secret key (fast path).
/// IND-CCA2: implicit rejection on failure. Fully branchless.
pub fn decapsulate_cached(
    seed: &[u8; SEED_BYTES],
    h0: &Circulant,
    h1: &Circulant,
    ct: &KemCiphertext,
) -> Result<[u8; SESSION_KEY_BYTES], ArcError> {
    decapsulate_with_polys(seed, h0, h1, ct)
}

/// Core decapsulation logic (shared by both entry points).
/// Fully branchless: decode returns (e0, e1, converged), no match/unwrap on secret.
fn decapsulate_with_polys(
    seed: &[u8; SEED_BYTES],
    h0: &Circulant,
    h1: &Circulant,
    ct: &KemCiphertext,
) -> Result<[u8; SESSION_KEY_BYTES], ArcError> {
    let s = Polynomial::from_bytes(&ct.syndrome);
    let s_prime = h0.compute_syndrome_ct(&s);

    // Decode: always returns (e0, e1, converged) — no branch on secret
    let (e0_decoded, e1_decoded, converged) = decode(&s_prime, h0, h1);

    // FO transform: always computed (branchless)
    let recomputed = h0
        .compute_syndrome_ct(&e0_decoded)
        .add(&h1.compute_syndrome_ct(&e1_decoded));
    let ct_ok: u8 = (recomputed.ct_bytes_equal(&s_prime) as u8).wrapping_neg();
    let w = e0_decoded.weight() + e1_decoded.weight();
    let w_ok: u8 = ((w == ERROR_WEIGHT) as u64).wrapping_neg() as u8;
    let fo_mask = ct_ok & w_ok;

    // Convert converged bool to mask (0xFF if true, 0x00 if false)
    let converged_mask: u8 = (converged as u64).wrapping_neg() as u8;
    let mask = fo_mask & converged_mask;

    let real_key: [u8; SESSION_KEY_BYTES] = {
        let e_bytes = [
            e0_decoded.as_bytes().as_slice(),
            e1_decoded.as_bytes().as_slice(),
        ]
        .concat();
        let mut key_input = Vec::with_capacity(16 + e_bytes.len());
        key_input.extend_from_slice(b"ARCB-KEM-KEY-V1");
        key_input.extend_from_slice(&e_bytes);
        blake3::hash(&key_input).into()
    };
    let reject_key = rejection_key(seed, ct);

    // Branchless select: key = (real & mask) | (reject & !mask)
    let mut key = [0u8; SESSION_KEY_BYTES];
    for i in 0..SESSION_KEY_BYTES {
        key[i] = (real_key[i] & mask) | (reject_key[i] & !mask);
    }
    Ok(key)
}

fn generate_error() -> (Polynomial, Polynomial) {
    debug_assert!(ERROR_WEIGHT <= 2 * M);
    let mut rng = OsRng;
    let mut bits = vec![0u8; 2 * M];
    let mut pos: Vec<usize> = (0..2 * M).collect();
    for i in 0..ERROR_WEIGHT {
        let j = rng.gen_range(i..2 * M);
        pos.swap(i, j);
        bits[pos[i]] = 1;
    }
    (
        Polynomial::from_bits(&bits[..M]).unwrap(),
        Polynomial::from_bits(&bits[M..]).unwrap(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen;

    #[test]
    fn test_kem_roundtrip() {
        let kp = keygen::from_seed_without_dfr([0xABu8; SEED_BYTES]).unwrap();
        let (ct, k1) = encapsulate(&kp.public);
        let k2 = decapsulate(&kp.seed, &ct).unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_kem_roundtrip_cached() {
        let kp = keygen::from_seed_without_dfr([0xCDu8; SEED_BYTES]).unwrap();
        let (h0p, h1p) = utils::derive_secret_polynomials(&kp.seed).unwrap();
        let h0 = Circulant::new(h0p);
        let h1 = Circulant::new(h1p);

        for _ in 0..5 {
            let (ct, k1) = encapsulate(&kp.public);
            let k2 = decapsulate_cached(&kp.seed, &h0, &h1, &ct).unwrap();
            assert_eq!(k1, k2);
        }
    }

    #[test]
    fn test_wrong_seed_fails() {
        let kp1 = keygen::from_seed_without_dfr([0x01u8; SEED_BYTES]).unwrap();
        let kp2 = keygen::from_seed_without_dfr([0x02u8; SEED_BYTES]).unwrap();
        let (ct, k1) = encapsulate(&kp1.public);
        let k_wrong = decapsulate(&kp2.seed, &ct).unwrap();
        assert_ne!(k_wrong, k1, "wrong seed should produce different key");
    }

    #[test]
    fn test_error_weight() {
        let (e0, e1) = generate_error();
        assert_eq!(e0.weight() + e1.weight(), ERROR_WEIGHT);
    }
}
