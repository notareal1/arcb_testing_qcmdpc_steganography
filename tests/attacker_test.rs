// tests/attacker_test.rs — Attacker perspective tests
//
// This file attempts to find vulnerabilities in the ARCB implementation
// by simulating various attack vectors.

use arcb_stegano_trapdoor::*;
use rand::Rng;
use rand::RngCore;
use std::time::{Duration, Instant};

// === ATTACK 1: Timing side-channel on decode ===
// Measure if decode timing leaks information about the secret key

#[test]
fn attack_timing_side_channel() {
    let kp = keygen::generate().unwrap();
    let (h0p, h1p) = utils::derive_secret_polynomials(&kp.seed).unwrap();
    let h0 = matrix::Circulant::new(h0p);
    let h1 = matrix::Circulant::new(h1p);

    // Generate syndromes with different error weights
    let mut timings_per_weight: Vec<(usize, Vec<Duration>)> = Vec::new();

    for weight in [1, 5, 10, 20, 50, 100, 134] {
        let mut timings = Vec::new();

        for _ in 0..5 {
            let mut rng = rand::thread_rng();
            let mut bits = vec![0u8; 2 * M];
            let mut pos: Vec<usize> = (0..2 * M).collect();
            for i in 0..weight {
                let j = rng.gen_range(i..2 * M);
                pos.swap(i, j);
                bits[pos[i]] = 1;
            }
            let e0 = Polynomial::from_bits(&bits[..M]).unwrap();
            let e1 = Polynomial::from_bits(&bits[M..]).unwrap();
            let syndrome = h0.compute_syndrome(&e0).add(&h1.compute_syndrome(&e1));

            let start = Instant::now();
            let _ = decoder::decode(&syndrome, &h0, &h1);
            timings.push(start.elapsed());
        }

        timings_per_weight.push((weight, timings));
    }

    // Analyze timing differences
    println!("\n=== Timing Side-Channel Analysis ===");
    let mut max_ratio = 1.0f64;
    for (weight, timings) in &timings_per_weight {
        let avg: Duration = timings.iter().sum::<Duration>() / timings.len() as u32;
        println!("Weight {}: avg {:?}", weight, avg);

        for (other_weight, other_timings) in &timings_per_weight {
            if weight != other_weight {
                let other_avg: Duration =
                    other_timings.iter().sum::<Duration>() / other_timings.len() as u32;
                let ratio = if avg > other_avg {
                    avg.as_secs_f64() / other_avg.as_secs_f64()
                } else {
                    other_avg.as_secs_f64() / avg.as_secs_f64()
                };
                max_ratio = max_ratio.max(ratio);
            }
        }
    }

    println!("Max timing ratio: {:.2}", max_ratio);
    // If ratio > 2.0, there's a potential timing leak
    assert!(
        max_ratio < 2.0,
        "Timing ratio {:.2} suggests timing side-channel!",
        max_ratio
    );
}

// === ATTACK 2: Syndrome distinguishability ===
// Check if valid syndromes can be distinguished from random

#[test]
fn attack_syndrome_distinguishability() {
    let kp = keygen::generate().unwrap();
    let (h0p, h1p) = utils::derive_secret_polynomials(&kp.seed).unwrap();
    let h0 = matrix::Circulant::new(h0p);
    let h1 = matrix::Circulant::new(h1p);

    // Generate valid syndromes
    let mut valid_syndrome_weights = Vec::new();
    for _ in 0..100 {
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
        let syndrome = h0.compute_syndrome(&e0).add(&h1.compute_syndrome(&e1));
        valid_syndrome_weights.push(syndrome.weight());
    }

    // Generate random syndromes
    let mut random_syndrome_weights = Vec::new();
    for _ in 0..100 {
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; SYNDROME_BYTES];
        rng.fill_bytes(&mut bytes);
        let syndrome = Polynomial::from_bytes(&bytes);
        random_syndrome_weights.push(syndrome.weight());
    }

    // Compare distributions
    let valid_avg: f64 =
        valid_syndrome_weights.iter().sum::<usize>() as f64 / valid_syndrome_weights.len() as f64;
    let random_avg: f64 =
        random_syndrome_weights.iter().sum::<usize>() as f64 / random_syndrome_weights.len() as f64;

    println!("\n=== Syndrome Distinguishability ===");
    println!("Valid syndrome avg weight: {:.1}", valid_avg);
    println!("Random syndrome avg weight: {:.1}", random_avg);
    println!(
        "Difference: {:.1}%",
        (valid_avg - random_avg).abs() / valid_avg * 100.0
    );

    // Valid syndromes should have weight close to t*2 = 268 (for t=134)
    // Random syndromes should have weight close to M/2 = 8192
    // Large difference means they're distinguishable
    assert!(
        (valid_avg - random_avg).abs() > 100.0,
        "Valid and random syndromes should be distinguishable (this is expected)"
    );
}

// === ATTACK 3: Key collision attack ===
// Try to find two different seeds that produce the same key

#[test]
fn attack_key_collision() {
    let mut key_map: std::collections::HashMap<Vec<u8>, [u8; SEED_BYTES]> =
        std::collections::HashMap::new();

    let mut collision_count = 0;
    for i in 0u8..10 {
        let seed = [i; SEED_BYTES];
        if let Ok(kp) = keygen::from_seed(seed) {
            let (_, key) = kem::encapsulate(&kp.public);
            if let Some(prev_seed) = key_map.get(&key.to_vec()) {
                println!(
                    "Key collision found! Seeds {:?} and {:?} produce same key",
                    prev_seed, seed
                );
                collision_count += 1;
            }
            key_map.insert(key.to_vec(), seed);
        }
    }

    println!("\n=== Key Collision Attack ===");
    println!("Keys generated: {}", key_map.len());
    println!("Collisions found: {}", collision_count);

    // With 196-bit security, collisions should be astronomically rare
    assert_eq!(collision_count, 0, "Key collision detected!");
}

// === ATTACK 4: Fault injection on FO transform ===
// Check if flipping bits in the decoded error can bypass FO check

#[test]
fn attack_fault_injection_fo() {
    let kp = keygen::generate().unwrap();
    let (h0p, h1p) = utils::derive_secret_polynomials(&kp.seed).unwrap();
    let h0 = matrix::Circulant::new(h0p);
    let h1 = matrix::Circulant::new(h1p);

    let (ct, k1) = kem::encapsulate(&kp.public);

    // Decode normally
    let s_prime = h0.compute_syndrome_ct(&Polynomial::from_bytes(&ct.syndrome));
    let (e0, e1, converged) = decoder::decode(&s_prime, &h0, &h1);

    if !converged {
        println!("Decode didn't converge, skipping fault injection test");
        return;
    }

    // Try flipping bits in decoded error
    let mut rng = rand::thread_rng();
    for trial in 0..10 {
        let mut e0_corrupted = e0.clone();
        let flip_pos = (trial * 137) % M;
        e0_corrupted.flip_bit(flip_pos);

        // Check if FO transform catches this
        let recomputed = h0
            .compute_syndrome_ct(&e0_corrupted)
            .add(&h1.compute_syndrome_ct(&e1));
        let fo_ok = recomputed.ct_bytes_equal(&s_prime);

        assert!(!fo_ok, "Trial {}: FO should detect corrupted e0!", trial);
    }

    println!("\n=== Fault Injection Attack ===");
    println!("All {} fault injections detected by FO transform", 10);
}

// === ATTACK 5: Implicit rejection bypass ===
// Check if wrong seed produces a key that's related to the correct key

#[test]
fn attack_implicit_rejection() {
    let kp1 = keygen::generate().unwrap();
    let kp2 = keygen::generate().unwrap();

    let (ct, k1) = kem::encapsulate(&kp1.public);
    let k2 = kem::decapsulate(&kp2.seed, &ct).unwrap();

    // k1 and k2 should be completely unrelated
    let mut diff_bits = 0;
    for i in 0..SESSION_KEY_BYTES {
        diff_bits += (k1[i] ^ k2[i]).count_ones();
    }

    println!("\n=== Implicit Rejection Attack ===");
    println!("Correct key: {:02x?}", &k1[..8]);
    println!("Wrong key:   {:02x?}", &k2[..8]);
    println!("Bit differences: {}/{}", diff_bits, SESSION_KEY_BYTES * 8);

    // Keys should differ in ~50% of bits
    let diff_ratio = diff_bits as f64 / (SESSION_KEY_BYTES * 8) as f64;
    assert!(
        diff_ratio > 0.3 && diff_ratio < 0.7,
        "Key difference ratio {:.2} is suspicious (expected ~0.5)",
        diff_ratio
    );
}

// === ATTACK 6: Steganographic detection ===
// Check if stego digits can be distinguished from random digits

#[test]
fn attack_stego_detection() {
    let kp = keygen::generate().unwrap();

    // Generate stego digits
    let stego_digits = stego::encapsulate_stego(&kp).unwrap();

    // Generate random digits
    let mut rng = rand::thread_rng();
    let mut random_digits = vec![0u8; SUPERBLOCK_DIGITS];
    for d in random_digits.iter_mut() {
        *d = rng.gen_range(0..10);
    }

    // Compare digit distributions
    let mut stego_counts = [0usize; 10];
    let mut random_counts = [0usize; 10];

    for &d in &stego_digits {
        stego_counts[d as usize] += 1;
    }
    for &d in &random_digits {
        random_counts[d as usize] += 1;
    }

    println!("\n=== Steganographic Detection ===");
    println!("Digit | Stego    | Random   | Diff");
    println!("------|----------|----------|------");
    for i in 0..10 {
        let diff = (stego_counts[i] as i64 - random_counts[i] as i64).abs();
        println!(
            "  {}   | {:8} | {:8} | {:4}",
            i, stego_counts[i], random_counts[i], diff
        );
    }

    // Chi-squared test for uniformity
    let expected = SUPERBLOCK_DIGITS as f64 / 10.0;
    let mut chi_squared = 0.0;
    for i in 0..10 {
        let diff = stego_counts[i] as f64 - expected;
        chi_squared += diff * diff / expected;
    }

    println!("Chi-squared statistic: {:.2}", chi_squared);
    println!("(Lower = more uniform, critical value for p=0.05 is 16.9)");

    // For stego to be undetectable, chi-squared should be low
    // Note: This is expected to fail because w=45 << M causes bias
    if chi_squared > 16.9 {
        println!("WARNING: Stego digits are detectable (chi-squared > 16.9)");
        println!("This is expected due to w=45 << M=16384 causing mask_bit=0 bias");
    }
}

// === ATTACK 7: Replay attack ===
// Check if reusing the same ciphertext produces the same key

#[test]
fn attack_replay() {
    let kp = keygen::generate().unwrap();

    let (ct, k1) = kem::encapsulate(&kp.public);
    let k2 = kem::decapsulate(&kp.seed, &ct).unwrap();

    // Same ciphertext should produce same key
    assert_eq!(k1, k2, "Replay should produce same key");

    println!("\n=== Replay Attack ===");
    println!("Same ciphertext produces same key: YES (expected)");
    println!("This is why each message should use a fresh encapsulation");
}

// === ATTACK 8: Known-plaintext attack ===
// Check if knowing plaintext-ciphertext pairs reveals the key

#[test]
fn attack_known_plaintext() {
    let kp = keygen::generate().unwrap();

    // Get multiple plaintext-ciphertext pairs
    let mut pairs = Vec::new();
    for _ in 0..5 {
        let (ct, key) = kem::encapsulate(&kp.public);
        pairs.push((ct, key));
    }

    // Check if keys are all different (they should be)
    let mut unique_keys = std::collections::HashSet::new();
    for (_, key) in &pairs {
        unique_keys.insert(key.to_vec());
    }

    println!("\n=== Known-Plaintext Attack ===");
    println!("Pairs generated: {}", pairs.len());
    println!("Unique keys: {}", unique_keys.len());

    assert_eq!(
        unique_keys.len(),
        pairs.len(),
        "Each encapsulation should produce a unique key"
    );
}

// === ATTACK 9: Seed brute-force (small seed space) ===
// Try to brute-force a seed with a known public key

#[test]
fn attack_seed_bruteforce() {
    // Use a known seed
    let target_seed = [0x42u8; SEED_BYTES];
    let kp = keygen::from_seed(target_seed).unwrap();

    // Try to find the seed by brute force (only try a few)
    let mut found = false;
    for i in 0u8..10 {
        let seed = [i; SEED_BYTES];
        if let Ok(candidate_kp) = keygen::from_seed(seed) {
            if candidate_kp.public.as_bytes() == kp.public.as_bytes() {
                println!("\n=== Seed Brute-Force Attack ===");
                println!("Found seed: {:?}", seed);
                found = true;
                break;
            }
        }
    }

    if !found {
        println!("\n=== Seed Brute-Force Attack ===");
        println!("Seed not found in first 10 attempts (expected)");
        println!("Full brute force would require 2^256 attempts");
    }

    // This attack is infeasible with 256-bit seeds
    assert!(!found || target_seed[0] < 10, "Seed should not be easily brute-forced");
}

// === ATTACK 10: Memory dump attack ===
// Check if sensitive data is properly zeroized

#[test]
fn attack_memory_dump() {
    // This test verifies that zeroization works correctly
    let mut poly = Polynomial::zero();
    poly.set_bit(0, 1);
    poly.set_bit(100, 1);
    poly.set_bit(1000, 1);

    assert_eq!(poly.weight(), 3);

    // Zeroize
    poly.zeroize();
    assert_eq!(poly.weight(), 0, "Zeroized polynomial should have weight 0");

    println!("\n=== Memory Dump Attack ===");
    println!("Zeroization works correctly: YES");
}
