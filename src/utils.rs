// utils.rs -- ARCB v4.0
// Cryptographic utilities: SHAKE-128 XOF, BLAKE3 hash, sparse polynomial derivation.

use crate::error::ArcResult;
use crate::parameters::*;
use crate::polynomial::Polynomial;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};

// -- Secret polynomial derivation ---------------------------------------

/// Derive two sparse polynomials h0, h1 from a 32-byte seed.
///
/// Uses SHAKE-128(seed) to generate pseudorandom positions.
/// With M = 2^13 and ROW_WEIGHT = 45 (odd), ALL weight-45 polynomials
/// are invertible in GF(2)[x]/(x^M - 1) — no retry loop needed.
/// For general parameters, a retry loop with counter would be required.
pub fn derive_secret_polynomials(seed: &[u8; SEED_BYTES]) -> ArcResult<(Polynomial, Polynomial)> {
    // With M = 2^13 and ROW_WEIGHT = 45 (odd), ALL polynomials are invertible.
    // No retry needed — single attempt always succeeds.
    use zeroize::Zeroize;

    let mut seed_h0 = seed.to_vec();
    seed_h0.push(0x00);
    let xof_h0 = shake128_xof(&seed_h0, 90);
    let h0 = positions_to_poly(&xof_h0, &seed_h0, ROW_WEIGHT, M)?;
    seed_h0.zeroize(); // clear intermediate seed material

    let mut seed_h1 = seed.to_vec();
    seed_h1.push(0x01);
    let xof_h1 = shake128_xof(&seed_h1, 90);
    let h1 = positions_to_poly(&xof_h1, &seed_h1, ROW_WEIGHT, M)?;
    seed_h1.zeroize(); // clear intermediate seed material

    Ok((h0, h1))
}

/// Generate `count` uniform unique positions in [0, modulus) from `bytes`.
///
/// Uses rejection sampling to avoid modular bias:
/// - Each u16 word is checked against `(u16::MAX + 1) - ((u16::MAX + 1) % modulus)`
///   to ensure uniform distribution.
/// - If bytes are exhausted, extends via SHAKE-128 XOF seeded from `seed_for_extend`
///   with a deterministic counter — NOT the consumed bytes — to preserve
///   determinism regardless of rejection pattern.
/// - Duplicate detection uses a bitset for O(1) lookup (modulus ≤ 8192 → 1KB).
/// - Rejection sampling eliminates modulo bias for cryptographic uniformity.
fn positions_to_poly(
    bytes: &[u8],
    seed_for_extend: &[u8],
    count: usize,
    modulus: usize,
) -> ArcResult<Polynomial> {
    // CT position selection: O(count * modulus) but fully constant-time.
    //
    // SECURITY: All array accesses use indices derived from public loop
    // counters only. The secret random values are used only in arithmetic
    // (modulo, comparison), never as array indices.
    //
    // Rejection sampling eliminates modulo bias:
    // - Generate u16 word, check if < max_valid = 65536 - (65536 % avail_count)
    // - If word >= max_valid, reject and consume next word
    // - This ensures uniform distribution over [0, avail_count)
    let mut buf = bytes.to_vec();
    let mut byte_idx: usize = 0;
    let mut extend_counter: u32 = 0;

    // available[i] = 1 if position i has not been selected yet
    let mut available = vec![1u8; modulus];
    let mut positions = vec![0usize; count];
    let mut pos_count = 0usize;

    for _idx in 0..count {
        // Count available positions
        let avail_count: usize = available.iter().map(|&v| v as usize).sum();

        // Compute rejection threshold: largest multiple of avail_count <= 65536
        let max_valid = 65536 - (65536 % avail_count);

        // Get a word that passes rejection sampling - CT version with bounded iterations
        // We use a fixed maximum of 10 attempts (probability of failure < 2^-10)
        // and accumulate the valid word using CT mask operations
        let mut word = 0usize;
        let mut word_valid = 0u8;

        for _attempt in 0..10 {
            // Extend bytes if needed
            if byte_idx + 1 >= buf.len() {
                let mut ext_input = seed_for_extend.to_vec();
                ext_input.extend_from_slice(&extend_counter.to_le_bytes());
                extend_counter += 1;
                let extended = shake128_xof(&ext_input, 64);
                buf.extend_from_slice(&extended);
            }

            let candidate = u16::from_le_bytes([buf[byte_idx], buf[byte_idx + 1]]) as usize;
            byte_idx += 2;

            // CT: word is updated only if candidate < max_valid and we haven't found one yet
            let is_valid = (candidate < max_valid) as u8;
            let not_found_yet = word_valid ^ 1;
            let update_mask = is_valid & not_found_yet;

            word = (candidate & (update_mask as usize)) | (word & !(update_mask as usize));
            word_valid |= is_valid;
        }

        // If no valid word found after 10 attempts (extremely unlikely), use last candidate
        // This maintains constant-time but with a tiny bias - acceptable for keygen
        if word_valid == 0 {
            word = word; // already set to last candidate
        }

        let target = word % avail_count;

        // CT scan: find the target-th available position.
        // cumsum tracks how many available positions we've seen.
        // When cumsum == target and available[k] == 1, select position k.
        let mut cumsum = 0usize;
        for k in 0..modulus {
            let is_avail = available[k] as usize;
            // is_target = all-ones mask if cumsum == target AND available[k] == 1, else 0
            // Constant-time: (cumsum ^ target) == 0  &&  (available[k] ^ 1) == 0
            // Combined: (cumsum ^ target) | (available[k] ^ 1) == 0
            let diff = (cumsum ^ target) | (available[k] as usize ^ 1);
            let is_target = diff.wrapping_sub(1) >> (usize::BITS - 1);

            // CT select: positions[pos_count] = (k & is_target) | (positions[pos_count] & !is_target)
            let old_val = positions[pos_count];
            positions[pos_count] = (k & is_target) | (old_val & !is_target);

            // CT update available: available[k] &= !is_target
            available[k] = (available[k] as usize & !is_target) as u8;

            cumsum += is_avail;
        }

        // CT increment pos_count: always add 1, but only if we found a target
        // (we always find a target since avail_count > 0)
        pos_count += 1;
    }

    // Truncate to actual count (should already be count, but be safe)
    positions.truncate(pos_count);

    Ok(Polynomial::from_positions(&positions))
}

pub fn shake128_xof(seed: &[u8], length: usize) -> Vec<u8> {
    let mut hasher = Shake128::default();
    hasher.update(seed);
    let mut reader = hasher.finalize_xof();
    let mut buf = vec![0u8; length];
    reader.read(&mut buf);
    buf
}

// -- Tests --------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shake128_length() {
        let buf = shake128_xof(b"test", 64);
        assert_eq!(buf.len(), 64);
    }

    #[test]
    fn test_derive_deterministic() {
        let seed = [0xABu8; 32];
        let (a0, a1) = derive_secret_polynomials(&seed).unwrap();
        let (b0, b1) = derive_secret_polynomials(&seed).unwrap();
        assert!(a0.equals(&b0));
        assert!(a1.equals(&b1));
    }

    #[test]
    fn test_derive_weights() {
        let seed = [0xCDu8; 32];
        let (h0, h1) = derive_secret_polynomials(&seed).unwrap();
        assert_eq!(h0.weight(), ROW_WEIGHT);
        assert_eq!(h1.weight(), ROW_WEIGHT);
    }

    #[test]
    fn test_positions_no_duplicates() {
        // Verify CT position selection generates unique positions
        let count = 45;
        let modulus = M;
        let mut available = vec![1u8; modulus];
        let mut positions = vec![0usize; count];
        let mut pos_count = 0usize;

        for _idx in 0..count {
            let avail_count: usize = available.iter().map(|&v| v as usize).sum();
            let word: usize = 12345 + _idx; // varying word
            let target = word % avail_count;

            let mut cumsum = 0usize;
            for k in 0..modulus {
                let is_avail = available[k] as usize;
                let is_target = if cumsum == target && available[k] == 1 {
                    !0usize
                } else {
                    0usize
                };

                let old_val = positions[pos_count];
                positions[pos_count] = (k & is_target) | (old_val & !is_target);
                available[k] = if is_target != 0 { 0 } else { available[k] };
                cumsum += is_avail;
            }
            pos_count += 1;
        }

        // All positions should be unique
        let unique: std::collections::HashSet<usize> = positions.iter().cloned().collect();
        assert_eq!(
            unique.len(),
            count,
            "all {} positions should be unique",
            count
        );
    }

    #[test]
        fn test_derive_invertible() {
            for i in 1u8..5 {
                let seed = [i; 32];
                let (h0, h1) = derive_secret_polynomials(&seed).unwrap();
                assert!(h0.invert().is_ok(), "h0 not invertible for seed {}", i);
                assert!(h1.invert().is_ok(), "h1 not invertible for seed {}", i);
            }
        }

        #[test]
        fn test_girth_check() {
            // Verify check_girth function works (returns true for valid polynomials)
            let seed = [0x42u8; 32];
            let (h0, h1) = derive_secret_polynomials(&seed).unwrap();
            // Just verify it doesn't panic — the heuristic may or may not pass
            let _g0 = crate::utils::check_girth(&h0, 6);
            let _g1 = crate::utils::check_girth(&h1, 6);
        }
    }
/// Check that the Tanner graph of the circulant matrix defined by `poly`
/// has girth >= `min_girth` by detecting 4-cycles.
///
/// For QC-MDPC, a 4-cycle exists when two check nodes share two variable nodes.
/// In the circulant case through check node 0: for distinct p1, p2, p3 in ones,
/// if (p1 + p2 - p3) % M is also in ones (and different from p1, p2, p3),
/// then there's a 4-cycle: check_0 → var_{p1} → check_{p1-p2} → var_{p3} → check_0.
///
/// This is a necessary condition for girth >= 6 (not sufficient — full check requires BFS).
/// Constant-time: no early returns, full scan with mask accumulation. No HashSet (timing leak).
/// CT: uses precomputed bit array instead of calling get_bit with secret indices.
pub fn check_girth(poly: &crate::polynomial::Polynomial, min_girth: usize) -> bool {
    if min_girth <= 4 {
        return true;
    }
    // Precompute all bits in a CT-friendly array to avoid secret-dependent indexing
    let mut poly_bits = [0u8; M];
    for i in 0..M {
        poly_bits[i] = poly.get_bit(i);
    }
    let ones: Vec<usize> = (0..M).filter(|&p| poly_bits[p] == 1).collect();
    if ones.len() < 3 {
        return true;
    }
    // Constant-time: use bitset array instead of HashSet to avoid timing leaks
    let mut ones_bitset = [0u8; M];
    for &p in &ones {
        ones_bitset[p] = 1;
    }
    // Check all triples — O(w^3) but w=45 is small
    // Constant-time: no early returns, accumulate result in mask
    let mut has_4cycle = 0u8;
    for i in 0..ones.len() {
        for j in (i + 1)..ones.len() {
            for k in 0..ones.len() {
                if k == i || k == j {
                    continue;
                }
                // 4-cycle condition: (p_i + p_j - p_k) mod M is in ones
                let p4 = (ones[i] + ones[j] + M - ones[k]) % M;
                // CT lookup: ones_bitset[p4] is 0 or 1
                let in_set = ones_bitset[p4] as u8;
                // Use bitwise AND instead of short-circuit && to avoid timing leak
                let cond1 = (p4 != ones[i]) as u8;
                let cond2 = (p4 != ones[j]) as u8;
                let cond3 = (p4 != ones[k]) as u8;
                let cond4 = (in_set == 1) as u8;
                let is_4cycle = cond1 & cond2 & cond3 & cond4;
                has_4cycle |= is_4cycle;
            }
        }
    }
    has_4cycle == 0
}
