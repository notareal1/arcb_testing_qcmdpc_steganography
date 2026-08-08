// keygen.rs -- ARCB v5.0 (Production)
// Key generation: p(x) = h0^{-1}(x) * h1(x) mod (x^M - 1)
//
// DFR check: generates random syndromes and attempts decode to estimate DFR.
// Keys with decode failures are rejected (indicates poor trapping set structure).

use crate::decoder::decode;
use crate::error::ArcError;
use crate::matrix::Circulant;
use crate::parameters::*;
use crate::polynomial::Polynomial;
use crate::utils;
use rand::Rng;
use zeroize::Zeroize;

#[derive(Debug)]
pub struct KeyPair {
    pub seed: [u8; SEED_BYTES],
    pub public: Polynomial,
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}

/// Number of DFR trials during key generation.
/// Each trial generates a random error vector, computes syndrome, and attempts decode.
/// If ANY trial fails, the key is rejected.
///
/// NOTE: This is a HEURISTIC check, not a formal DFR proof. With N trials,
/// we detect keys with DFR >~ 1/N with high confidence, but we cannot
/// guarantee DFR < 2^-128 (the theoretical requirement for reaction attacks).
/// For production security, consider:
/// 1. Using N >= 200 trials (P(miss 5% DFR) < 0.003%)
/// 2. Combining with girth check (already implemented)
/// 3. Using theoretical DFR bounds from QC-MDPC literature
///
/// Test builds use fewer trials for speed; production builds use 100.
/// P(miss a 5% DFR key): 0.95^10 ≈ 60% (test) vs 0.95^100 ≈ 0.6% (production)
#[cfg(test)]
const DFR_TRIALS: usize = 10;

#[cfg(not(test))]
const DFR_TRIALS: usize = 100;

/// Generate a fresh key pair from OS entropy with DFR check.
pub fn generate() -> Result<KeyPair, ArcError> {
    let mut seed = [0u8; SEED_BYTES];
    getrandom::getrandom(&mut seed)
        .map_err(|e| ArcError::RngError(format!("OS entropy: {}", e)))?;
    from_seed_with_check(seed)
}

/// Deterministically derive a key pair from a 32-byte seed with DFR check.
pub fn from_seed(seed: [u8; SEED_BYTES]) -> Result<KeyPair, ArcError> {
    from_seed_with_check(seed)
}

/// Deterministically derive a key pair WITHOUT DFR check.
/// WARNING: Only use in tests or trusted environments. Production code should
/// use `from_seed` or `generate` which include DFR validation.
pub fn from_seed_without_dfr(seed: [u8; SEED_BYTES]) -> Result<KeyPair, ArcError> {
    let (h0, h1) = utils::derive_secret_polynomials(&seed)?;
    let h0_inv = h0.invert().ok_or(ArcError::KeyGenError)?;
    let public = h0_inv.multiply(&h1);
    Ok(KeyPair { seed, public })
}

fn from_seed_with_check(seed: [u8; SEED_BYTES]) -> Result<KeyPair, ArcError> {
    let (h0, h1) = utils::derive_secret_polynomials(&seed)?;
    let h0_inv = h0.invert().ok_or(ArcError::KeyGenError)?;
    let public = h0_inv.multiply(&h1);

    // Girth check: reject keys with 4-cycles in Tanner graph (girth < 6)
    // This is a heuristic — catches many bad keys before expensive DFR check.
    if !utils::check_girth(&h0, 6) || !utils::check_girth(&h1, 6) {
        return Err(ArcError::KeyGenError);
    }

    // DFR check: verify decoder works on random syndromes for this key
    let h0_circ = Circulant::new(h0.clone());
    let h1_circ = Circulant::new(h1.clone());
    let mut rng = rand::thread_rng();

    for _ in 0..DFR_TRIALS {
        // Generate random error vector of correct weight
        let mut bits = vec![0u8; 2 * M];
        let mut pos: Vec<usize> = (0..2 * M).collect();
        for i in 0..ERROR_WEIGHT {
            let j = rng.gen_range(i..2 * M);
            pos.swap(i, j);
            bits[pos[i]] = 1;
        }
        let e0 = Polynomial::from_bits(&bits[..M])?;
        let e1 = Polynomial::from_bits(&bits[M..])?;

        // Compute syndrome (non-CT is safe here: e0/e1 are random test vectors,
        // not attacker-controlled. Only h0/h1 positions are secret, and we
        // access h_words indexed by e bits — this does not leak h structure.)
        let syndrome = h0_circ
            .compute_syndrome(&e0)
            .add(&h1_circ.compute_syndrome(&e1));

        // Attempt decode
        let (d0, d1, converged) = decode(&syndrome, &h0_circ, &h1_circ);
        if !converged || !d0.equals(&e0) || !d1.equals(&e1) {
            return Err(ArcError::KeyGenError);
        }
    }

    Ok(KeyPair { seed, public })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_seed_deterministic() {
        let seed = [0xABu8; SEED_BYTES];
        let kp1 = from_seed_without_dfr(seed).unwrap();
        let kp2 = from_seed_without_dfr(seed).unwrap();
        assert!(kp1.public.equals(&kp2.public));
    }

    #[test]
    fn test_generate_nonzero() {
        let kp = from_seed_without_dfr([0x42u8; SEED_BYTES]).unwrap();
        assert!(!kp.public.is_zero());
    }

    #[test]
    fn test_pubkey_size() {
        let kp = from_seed_without_dfr([0x42u8; SEED_BYTES]).unwrap();
        assert_eq!(kp.public.as_bytes().len(), PUBKEY_BYTES);
    }

    #[test]
    fn test_different_seeds() {
        let mut keys = Vec::new();
        for i in 0u8..3 {
            let kp = from_seed_without_dfr([i; SEED_BYTES]).unwrap();
            keys.push(kp);
        }
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert!(
                    !keys[i].public.equals(&keys[j].public),
                    "keys {} and {} should differ",
                    i, j
                );
            }
        }
    }
}
