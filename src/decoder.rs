// decoder.rs -- ARCB v5.12 (Production)
// BGF decoder for QC-MDPC syndrome decoding.
// M=16384, w=45, t=134, MAX_ITER=12
//
// CT suspect computation: scan-all 256 words with bitwise equality
// to select values. ones_h0/ones_h1 are SECRET key positions, so
// direct array indexing would leak via cache timing.
//
// Security: constant-time syndrome, CT convergence check, branchless
// key selection, zeroize temp buffers.
// FIXED-LATENCY: All iterations perform identical work regardless of convergence.

use crate::matrix::bytes_to_words;
use crate::matrix::Circulant;
use crate::matrix::NUM_WORDS;
use crate::parameters::*;
use crate::polynomial::Polynomial;

const T_BLACK_INIT: u8 = 40;
const T_BLACK_FINAL: u8 = 20;
const T_GRAY_INIT: u8 = 30;
const T_GRAY_FINAL: u8 = 12;
const GRAY_COUNT_MIN: u16 = 2;
const BLACK_ONLY_ITERS: usize = 7;

pub fn decode(
    target: &Polynomial, h0: &Circulant, h1: &Circulant,
) -> (Polynomial, Polynomial, bool) {
    let mut e0 = Polynomial::zero();
    let mut e1 = Polynomial::zero();
    let mut gray_count = vec![0u16; 2 * M];
    let mut suspect = vec![0u8; 2 * M];
    let ones_h0 = h0.ones().to_vec();
    let ones_h1 = h1.ones().to_vec();
    let mut converged_mask: u8 = 0x00;

    for iter in 0..MAX_ITER {
        // Adaptive thresholds (integer linear interpolation, fully CT)
        let denom = if MAX_ITER > 1 { (MAX_ITER - 1) as u64 } else { 1 };
        let t_black = (T_BLACK_INIT as u64
            - ((T_BLACK_INIT as u64 - T_BLACK_FINAL as u64) * iter as u64) / denom) as u8;
        let t_gray = (T_GRAY_INIT as u64
            - ((T_GRAY_INIT as u64 - T_GRAY_FINAL as u64) * iter as u64) / denom) as u8;

        // Compute syndrome — fully constant-time bitsliced version
        let s_curr = h0.compute_syndrome_ct(&e0).add(&h1.compute_syndrome_ct(&e1));

        // CT convergence check
        let match_flag: u8 = s_curr.ct_bytes_equal(target) as u8;
        converged_mask = converged_mask | match_flag.wrapping_neg();

        // Work mask: 0xFF if still working, 0x00 if converged (neutralize all updates)
        let work_mask: u8 = !converged_mask;

        // Compute diff (suppressed if converged — branchless)
        let diff = s_curr.xor(target);
        let mut diff_bytes = *diff.as_bytes();
        for i in 0..PUBKEY_BYTES {
            diff_bytes[i] &= work_mask;
        }

        // Convert diff_bytes to word-level for fast bit extraction.
        let diff_words = bytes_to_words(&diff_bytes);

        // Compute suspect counts for h0 half.
        // SECURITY: ones_h0 contains SECRET key positions. We must NOT index
        // diff_words with secret-dependent indices. Instead, for each bit
        // position j, we scan ALL diff_words entries and use bitwise equality
        // to conditionally accumulate — same pattern as compute_syndrome_ct.
        for j in 0..M {
            let mut count = 0u8;
            for &p in &ones_h0 {
                let target_bit = (j + p) % M;
                let target_word_idx = target_bit >> 6;
                let target_bit_pos = target_bit & 63;
                // CT gather: scan all words, select using bitwise equality
                let mut word_val = 0u64;
                for k in 0..NUM_WORDS {
                    let diff = (k as u32 ^ target_word_idx as u32).wrapping_sub(1);
                    let mask = ((diff >> 31) as u64).wrapping_neg();
                    word_val |= diff_words[k] & mask;
                }
                count = count.wrapping_add((word_val >> target_bit_pos) as u8 & 1);
            }
            // Neutralize suspect when converged (mask with work_mask)
            suspect[j] = count & work_mask;
        }

        // Compute suspect counts for h1 half.
        for j in 0..M {
            let mut count = 0u8;
            for &p in &ones_h1 {
                let target_bit = (j + p) % M;
                let target_word_idx = target_bit >> 6;
                let target_bit_pos = target_bit & 63;
                // CT gather: scan all words, select using bitwise equality
                let mut word_val = 0u64;
                for k in 0..NUM_WORDS {
                    let diff = (k as u32 ^ target_word_idx as u32).wrapping_sub(1);
                    let mask = ((diff >> 31) as u64).wrapping_neg();
                    word_val |= diff_words[k] & mask;
                }
                count = count.wrapping_add((word_val >> target_bit_pos) as u8 & 1);
            }
            suspect[M + j] = count & work_mask;
        }

        // Flip bits based on BGF rules (branchless flip, masked by work_mask)
        let use_gray = iter >= BLACK_ONLY_ITERS;
        for j in 0..M {
            flip_bgf(&mut e0, &mut gray_count, j, j, suspect[j], t_black, t_gray, GRAY_COUNT_MIN, use_gray, work_mask);
        }
        for j in 0..M {
            let s = M + j;
            flip_bgf(&mut e1, &mut gray_count, j, s, suspect[s], t_black, t_gray, GRAY_COUNT_MIN, use_gray, work_mask);
        }
    }

    // Final convergence check (CT)
    let s_final = h0.compute_syndrome_ct(&e0).add(&h1.compute_syndrome_ct(&e1));
    let final_ok: u8 = s_final.ct_bytes_equal(target) as u8;
    let any_ok = converged_mask | final_ok.wrapping_neg();

    // Zeroize temp buffers that contain syndrome-derived data
    for v in gray_count.iter_mut() { *v = 0; }
    for v in suspect.iter_mut() { *v = 0; }

    (e0, e1, any_ok != 0)
}

#[inline]
fn flip_bgf(
    e: &mut Polynomial,
    gray_count: &mut [u16],
    bit_idx: usize,
    gray_idx: usize,
    suspect: u8,
    t_black: u8,
    t_gray: u8,
    gray_count_min: u16,
    use_gray: bool,
    work_mask: u8,
) {
    let sus = suspect as u64;
    let gc = gray_count[gray_idx] as u64;
    let tb = t_black as u64;
    let tg = t_gray as u64;
    let gcm = gray_count_min as u64;

    let ge_tb = ((sus.wrapping_sub(tb)) >> 63) ^ 1u64;
    let ge_tg = ((sus.wrapping_sub(tg)) >> 63) ^ 1u64;
    let lt_tb = (sus.wrapping_sub(tb)) >> 63;
    let gc_ok = ((gc.wrapping_sub(gcm)) >> 63) ^ 1u64;

    let black_flip = ge_tb;
    let use_gray_mask = if use_gray { !0u64 } else { 0u64 };
    let gray_flip = use_gray_mask & gc_ok & ge_tg & lt_tb;
    let flip_mask = (black_flip | gray_flip) & (work_mask as u64);

    e.flip_bit_ct(bit_idx, (flip_mask & 1) as u8);
    let in_gray_or_flip = (flip_mask | (ge_tg & use_gray_mask)) & (work_mask as u64);
    gray_count[gray_idx] = ((gc + 1) * in_gray_or_flip) as u16;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils;
    use rand::Rng;

    #[test]
    fn test_decode_zero() {
        let seed = [0xABu8; SEED_BYTES];
        let (h0p, h1p) = utils::derive_secret_polynomials(&seed).unwrap();
        let h0 = Circulant::new(h0p);
        let h1 = Circulant::new(h1p);
        let (e0, e1, converged) = decode(&Polynomial::zero(), &h0, &h1);
        assert!(converged);
        assert!(e0.is_zero() && e1.is_zero());
    }

    #[test]
    fn test_decode_t1() {
        let seed = [0x42u8; SEED_BYTES];
        let (h0p, h1p) = utils::derive_secret_polynomials(&seed).unwrap();
        let h0 = Circulant::new(h0p.clone());
        let h1 = Circulant::new(h1p.clone());

        for trial in 0u8..5 {
            let mut rng = rand::thread_rng();
            let mut bits = vec![0u8; 2 * M];
            let j = rng.gen_range(0..2 * M);
            bits[j] = 1;

            let e0 = Polynomial::from_bits(&bits[..M]).unwrap();
            let e1 = Polynomial::from_bits(&bits[M..]).unwrap();
            let s = h0.compute_syndrome(&e0).add(&h1.compute_syndrome(&e1));

            let (d0, d1, converged) = decode(&s, &h0, &h1);
            assert!(converged, "t=1 trial {trial} (pos={j}) failed");
            assert!(d0.equals(&e0) && d1.equals(&e1), "t=1 trial {trial} mismatch");
        }
    }

    #[test]
    #[ignore]
    fn test_decode_t134_dfr() {
        let seed = [0xABu8; SEED_BYTES];
        let (h0p, h1p) = utils::derive_secret_polynomials(&seed).unwrap();
        let h0 = Circulant::new(h0p.clone());
        let h1 = Circulant::new(h1p.clone());

        let mut successes = 0;
        let attempts = 3;
        for trial in 0..attempts {
            let mut rng = rand::thread_rng();
            let mut bits = vec![0u8; 2 * M];
            let mut pos: Vec<usize> = (0..2 * M).collect();
            for i in 0..ERROR_WEIGHT {
                let j = rng.gen_range(i..2 * M);
                pos.swap(i, j);
                bits[pos[i]] = 1;
            }

            let e0 = Polynomial::from_bits(&bits[..M]).unwrap();
            let e1 = Polynomial::from_bits(&bits[M..]).unwrap();
            let s = h0.compute_syndrome(&e0).add(&h1.compute_syndrome(&e1));

            let (d0, d1, converged) = decode(&s, &h0, &h1);
            if converged && d0.equals(&e0) && d1.equals(&e1) { successes += 1; }
            eprintln!("t=134 trial {trial}: {}/{} successes", successes, trial + 1);
        }
        eprintln!("t=134 DFR: {successes}/{attempts} successes");
        assert!(successes >= attempts * 8 / 10, "t=134: only {successes}/{attempts} successes");
    }
}
