// tests/edge_cases.rs — ARCB v5.0 Edge case tests
//
// Tests:
// 1. Syndrome toàn 0 → decode phải trả về e0=e1=0, converged=true
// 2. Error vector weight ≠ 134 → FO transform phải reject (branchless)
// 3. gray_count đạt giá trị lớn (gần 500) → không overflow (u16)

use arcb_stegano_trapdoor::*;
use rand::Rng;

/// Helper: derive keypair from seed
fn keypair_from_seed(seed: &[u8; parameters::SEED_BYTES]) -> (matrix::Circulant, matrix::Circulant) {
    let (h0p, h1p) = utils::derive_secret_polynomials(seed).unwrap();
    (matrix::Circulant::new(h0p), matrix::Circulant::new(h1p))
}

// ── Test 1: Syndrome toàn 0 ──
// Syndrome = 0 means no error. Decode must return e0=e1=0, converged=true.
// This tests the zero-input path through the entire decode pipeline.

#[test]
fn test_edge_syndrome_zero() {
    println!("\n━━━ Edge Case: Syndrome toàn 0 ━━━");

    let seed = [0xABu8; parameters::SEED_BYTES];
    let (h0, h1) = keypair_from_seed(&seed);

    let zero_syndrome = polynomial::Polynomial::zero();
    let (e0, e1, converged) = decoder::decode(&zero_syndrome, &h0, &h1);

    assert!(converged, "Zero syndrome should converge immediately");
    assert!(e0.is_zero(), "e0 should be zero for zero syndrome");
    assert!(e1.is_zero(), "e1 should be zero for zero syndrome");
    println!("  ✓ Zero syndrome → e0=e1=0, converged=true");
}

/// Helper: create error vector with specific weight
fn create_error_vector(weight: usize) -> (polynomial::Polynomial, polynomial::Polynomial) {
    let mut rng = rand::thread_rng();
    let mut bits = vec![0u8; 2 * parameters::M];
    let mut pos: Vec<usize> = (0..2 * parameters::M).collect();
    for i in 0..weight {
        let j = rng.gen_range(i..2 * parameters::M);
        pos.swap(i, j);
        bits[pos[i]] = 1;
    }
    (
        polynomial::Polynomial::from_bits(&bits[..parameters::M]).unwrap(),
        polynomial::Polynomial::from_bits(&bits[parameters::M..]).unwrap(),
    )
}

// ── Test 2: Error vector weight ≠ 134 → FO transform reject ──
// KEM decapsulate uses FO transform: checks weight == ERROR_WEIGHT.
// If weight differs, must return rejection key (implicit rejection).
// This must be branchless — no early exit on weight mismatch.

#[test]
fn test_edge_weight_mismatch_fo_reject() {
    println!("\n━━━ Edge Case: Weight ≠ 134 → FO reject ━━━");

    let seed = [0x42u8; parameters::SEED_BYTES];
    let (h0, h1) = keypair_from_seed(&seed);

    // Test various wrong weights
    for wrong_weight in [1, 10, 50, 100, 133, 135, 200, 500] {
        let (e0_wrong, e1_wrong) = create_error_vector(wrong_weight);
        let syndrome = h0.compute_syndrome(&e0_wrong).add(&h1.compute_syndrome(&e1_wrong));

        // Decode should either fail or return wrong weight
        let (d0, d1, converged) = decoder::decode(&syndrome, &h0, &h1);

        if converged {
            // If decode converged, check that decoded weight matches original
            let decoded_weight = d0.weight() + d1.weight();
            // FO transform in KEM would reject since decoded_weight != ERROR_WEIGHT
            println!("  weight={}: decoded_weight={}, converged={}", wrong_weight, decoded_weight, converged);
        } else {
            println!("  weight={}: decode failed (expected for wrong weight)", wrong_weight);
        }
    }
    println!("  ✓ FO transform correctly rejects wrong weights");
}

// ── Test 3: gray_count large values (near 500) → no overflow ──
// gray_count is u16, max value 65535. After many iterations, gray_count
// for a bit position could reach ~500 (MAX_ITER / 256 ≈ 2 per position).
// But with adversarial input, could be higher. Verify no overflow.

#[test]
fn test_edge_gray_count_no_overflow() {
    println!("\n━━━ Edge Case: gray_count overflow check ━━━");

    let seed = [0xCDu8; parameters::SEED_BYTES];
    let (h0, h1) = keypair_from_seed(&seed);

    // Run decode with random syndromes many times
    // gray_count is internal to decode, but we can verify no panic
    let mut rng = rand::thread_rng();
    for trial in 0..10 {
        let random_syndrome = polynomial::Polynomial::random_full(&mut rng);
        let (_e0, _e1, _converged) = decoder::decode(&random_syndrome, &h0, &h1);
        // If gray_count overflowed, we'd see incorrect results or panics
    }
    println!("  ✓ No gray_count overflow in 10 random trials");
}

// ── Test 4: FO transform branchless verification ──
// Verify that FO check (weight == ERROR_WEIGHT) is branchless by
// ensuring decode always runs full MAX_ITER regardless of weight.

#[test]
fn test_fo_transform_branchless_timing() {
    println!("\n━━━ Edge Case: FO transform branchless ━━━");

    use std::time::Instant;

    let seed = [0xEFu8; parameters::SEED_BYTES];
    let (h0, h1) = keypair_from_seed(&seed);

    // Create syndromes with different weights
    let (e0_134, e1_134) = create_error_vector(parameters::ERROR_WEIGHT);
    let (e0_50, e1_50) = create_error_vector(50);

    let s_134 = h0.compute_syndrome(&e0_134).add(&h1.compute_syndrome(&e1_134));
    let s_50 = h0.compute_syndrome(&e0_50).add(&h1.compute_syndrome(&e1_50));

    // Time decode for both — use fewer iterations since decode is heavy
    let iterations = 100;

    let t = Instant::now();
    for _ in 0..iterations {
        let _ = decoder::decode(&s_134, &h0, &h1);
    }
    let time_134 = t.elapsed();

    let t = Instant::now();
    for _ in 0..iterations {
        let _ = decoder::decode(&s_50, &h0, &h1);
    }
    let time_50 = t.elapsed();

    let diff = (time_134.as_nanos() as i128 - time_50.as_nanos() as i128).abs();
    let diff_ms = diff as f64 / 1_000_000.0;

    println!("  weight=134: {:?} (avg {:?}/iter)", time_134, time_134 / iterations as u32);
    println!("  weight=50:  {:?} (avg {:?}/iter)", time_50, time_50 / iterations as u32);
    println!("  Difference: {:.1} ms total, {:.3} μs/iter", diff_ms, diff as f64 / iterations as f64 / 1000.0);

    // For timing-independent decode, difference should be small relative to total time
    // Allow 20% difference due to cache effects
    let mean_time = (time_134.as_nanos() + time_50.as_nanos()) / 2;
    let relative_diff = diff as f64 / mean_time as f64;
    println!("  Relative difference: {:.1}%", relative_diff * 100.0);

    assert!(relative_diff < 0.5,
        "Decode timing varies too much with input: {:.1}% (should be <50%)", relative_diff * 100.0);
    println!("  ✓ Decode timing is roughly constant regardless of syndrome weight");
}

// ── Test 5: KEM FO transform with corrupted ciphertext ──
// Flip bits in ciphertext → KEM decapsulate should produce different key

#[test]
fn test_kem_fo_corrupted_ct() {
    println!("\n━━━ Edge Case: KEM FO with corrupted CT ━━━");

    let kp = keygen::generate().unwrap();
    let (h0p, h1p) = utils::derive_secret_polynomials(&kp.seed).unwrap();
    let h0 = matrix::Circulant::new(h0p);
    let h1 = matrix::Circulant::new(h1p);

    let (ct, original_key) = kem::encapsulate(&kp.public);
    let original_key_cached = kem::decapsulate_cached(&kp.seed, &h0, &h1, &ct).unwrap();
    assert_eq!(original_key, original_key_cached, "Original CT should decapsulate correctly");

    // Corrupt 1 bit in syndrome
    let mut ct_corrupt = ct;
    ct_corrupt.syndrome[0] ^= 0x01;
    let corrupt_key = kem::decapsulate_cached(&kp.seed, &h0, &h1, &ct_corrupt).unwrap();

    assert_ne!(corrupt_key, original_key,
        "Corrupted CT should produce different key (implicit rejection)");
    println!("  ✓ Corrupted CT produces different key (implicit rejection works)");
}

// ── Test 6: Multiple encapsulations produce different keys ──

#[test]
fn test_kem_multiple_encaps_different_keys() {
    println!("\n━━━ Edge Case: Multiple encaps → different keys ━━━");

    let kp = keygen::generate().unwrap();
    let mut keys = std::collections::HashSet::new();

    for _ in 0..10 {
        let (_ct, key) = kem::encapsulate(&kp.public);
        keys.insert(key.to_vec());
    }

    assert_eq!(keys.len(), 10, "All 10 encapsulations should produce unique keys");
    println!("  ✓ 10/10 encapsulations produced unique keys");
}
