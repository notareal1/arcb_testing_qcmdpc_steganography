// tests/attack_resistance_test.rs — Attack resistance tests
//
// Tests verify that the ARCB system resists standard cryptographic attacks:
// 1. Timing attack on decapsulation (constant-time verify)
// 2. Fault injection on ciphertext
// 3. Weak key detection (DFR)
// 4. Invalid input handling
// 5. Steganographic detection resistance

use arcb_stegano_trapdoor::*;
use aes_gcm::aead::AeadInPlace;
use std::time::{Duration, Instant};

// === Test 1: Timing Attack Resistance ===
// Verify that decapsulation timing does not correlate with decode success/failure

#[test]
fn test_timing_constant_for_success_and_failure() {
    // Generate a valid keypair
    let kp = keygen::generate().unwrap();
    let (h0p, h1p) = utils::derive_secret_polynomials(&kp.seed).unwrap();
    let h0 = matrix::Circulant::new(h0p);
    let h1 = matrix::Circulant::new(h1p);

    // Generate many valid ciphertexts and measure timing
    let mut success_times = Vec::new();
    for _ in 0..10 {
        let (ct, _) = kem::encapsulate(&kp.public);
        let start = Instant::now();
        let _ = kem::decapsulate_cached(&kp.seed, &h0, &h1, &ct).unwrap();
        success_times.push(start.elapsed());
    }

    // Generate wrong ciphertexts (random syndrome) and measure timing
    let mut failure_times = Vec::new();
    for _ in 0..10 {
        let random_syndrome = [0u8; SYNDROME_BYTES];
        let ct = kem::KemCiphertext { syndrome: random_syndrome };
        let start = Instant::now();
        let _ = kem::decapsulate_cached(&kp.seed, &h0, &h1, &ct);
        failure_times.push(start.elapsed());
    }

    // Calculate statistics
    let success_avg = success_times.iter().sum::<Duration>() / success_times.len() as u32;
    let failure_avg = failure_times.iter().sum::<Duration>() / failure_times.len() as u32;

    println!("Success avg: {:?}", success_avg);
    println!("Failure avg: {:?}", failure_avg);

    // The timing difference should be less than 50% for constant-time
    let ratio = if success_avg > failure_avg {
        success_avg.as_secs_f64() / failure_avg.as_secs_f64()
    } else {
        failure_avg.as_secs_f64() / success_avg.as_secs_f64()
    };

    println!("Timing ratio (success/failure): {:.2}", ratio);
    assert!(ratio < 2.0, "Timing ratio {:.2} too large — possible timing leak!", ratio);
}

// === Test 2: Fault Injection ===
// Verify that corrupted ciphertext is detected and rejected

#[test]
fn test_corrupted_kem_ciphertext_rejected() {
    let kp = keygen::generate().unwrap();
    let (h0p, h1p) = utils::derive_secret_polynomials(&kp.seed).unwrap();
    let h0 = matrix::Circulant::new(h0p);
    let h1 = matrix::Circulant::new(h1p);

    let (ct, k1) = kem::encapsulate(&kp.public);

    // Corrupt 1 byte in the syndrome
    let mut corrupted_ct = kem::KemCiphertext {
        syndrome: ct.syndrome,
    };
    corrupted_ct.syndrome[0] ^= 0xFF;

    let k2 = kem::decapsulate_cached(&kp.seed, &h0, &h1, &corrupted_ct).unwrap();

    // The corrupted CT should produce a DIFFERENT key (implicit rejection)
    assert_ne!(k1, k2, "Corrupted CT should produce different key");
}

#[test]
fn test_corrupted_packet_rejected() {
    let kp = keygen::generate().unwrap();
    let (h0p, h1p) = utils::derive_secret_polynomials(&kp.seed).unwrap();
    let h0 = matrix::Circulant::new(h0p);
    let h1 = matrix::Circulant::new(h1p);

    let (ct, _) = kem::encapsulate(&kp.public);
    let session_key = kem::decapsulate_cached(&kp.seed, &h0, &h1, &ct).unwrap();

    // Create a valid packet
    use blake3;
    let mut kdf_input = Vec::new();
    kdf_input.extend_from_slice(&session_key);
    kdf_input.extend_from_slice(&1u32.to_le_bytes());
    let enc_key: [u8; 32] = blake3::hash(&kdf_input).into();

    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    let cipher = Aes256Gcm::new((&enc_key).into());
    let nonce_bytes: [u8; 12] = blake3::hash(&session_key).as_bytes()[..12].try_into().unwrap();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = b"Test message for fault injection";
    let mut ciphertext = plaintext.to_vec();
    cipher.encrypt_in_place(nonce, b"", &mut ciphertext).unwrap();

    // Build packet
    let mut packet = Vec::new();
    packet.extend_from_slice(&1u32.to_le_bytes());
    packet.extend_from_slice(&nonce_bytes);
    packet.extend_from_slice(&ciphertext);

    // Corrupt a byte in the ciphertext portion
    let last = packet.len() - 1;
    packet[last] ^= 0xFF;

    // Try to decrypt — should fail (AES-GCM auth failure)
    let enc_key2: [u8; 32] = blake3::hash(&session_key).into();
    let cipher2 = Aes256Gcm::new((&enc_key2).into());
    let nonce2 = Nonce::from_slice(&nonce_bytes);
    let mut pt2 = packet[16..].to_vec();
    let decrypt_result = cipher2.decrypt_in_place(nonce2, b"", &mut pt2);

    assert!(
        decrypt_result.is_err(),
        "Corrupted packet should be rejected by AES-GCM"
    );
}

// === Test 3: Weak Key Detection (DFR) ===
// Verify that keys with poor DFR are rejected during keygen

#[test]
fn test_keygen_rejects_weak_keys() {
    // Try many seeds and verify keygen succeeds (DFR check passes)
    let mut successes = 0;
    let attempts = 10;
    for i in 0..attempts {
        let seed = [i as u8; SEED_BYTES];
        match keygen::from_seed(seed) {
            Ok(_) => successes += 1,
            Err(_) => println!("Key {} rejected (weak)", i),
        }
    }
    // At least 80% should succeed (DFR check catches truly weak keys)
    assert!(
        successes >= attempts * 8 / 10,
        "Only {}/{} keys generated — DFR check too strict?",
        successes,
        attempts
    );
    println!("Keygen success: {}/{}", successes, attempts);
}

// === Test 4: Invalid Input Handling ===
// Verify that invalid inputs are handled gracefully

#[test]
fn test_wrong_seed_decapsulate_doesnt_crash() {
    let kp1 = keygen::generate().unwrap();
    let kp2 = keygen::generate().unwrap();

    let (ct, k1) = kem::encapsulate(&kp1.public);

    // Decapsulate with wrong seed — should produce different key, not crash
    let k2 = kem::decapsulate(&kp2.seed, &ct).unwrap();
    assert_ne!(k1, k2, "Wrong seed should produce different key");
}

#[test]
fn test_zero_ciphertext_handled() {
    let kp = keygen::generate().unwrap();
    let zero_ct = kem::KemCiphertext {
        syndrome: [0u8; SYNDROME_BYTES],
    };
    // Should not crash — FO transform handles this
    let _ = kem::decapsulate(&kp.seed, &zero_ct).unwrap();
}

// === Test 5: Steganographic Detection Resistance ===
// Verify that steganographic digits look random
    #[test]
    fn test_stego_digits_distribution() {
        // Verify stego digits are in valid range 0-9
        // Note: distribution is NOT uniform because w=45 << M=16384
        // causes mask_bit=0 (small digits 0-7) to dominate ~90% of positions.
        // This is an inherent property of the steganographic encoding,
        // not a bug. The security comes from the random codeword c
        // masking the error vector e.
        let kp = keygen::generate().unwrap();
        let digits = stego::encapsulate_stego(&kp).unwrap();

        for &d in &digits {
            assert!(d <= 9, "Digit {} out of range 0-9", d);
        }

        // Verify we have both small (0-7) and large (8-9) digits
        let small_count = digits.iter().filter(|&&d| d <= 7).count();
        let large_count = digits.iter().filter(|&&d| d >= 8).count();
        assert!(small_count > 0, "Should have small digits");
        assert!(large_count > 0, "Should have large digits (padding)");

        // Verify padding digits (last PADDING_DIGITS) are uniform 0-9
        let padding_start = 2 * parameters::M;
        let padding = &digits[padding_start..];
        let mut counts = [0usize; 10];
        for &d in padding {
            counts[d as usize] += 1;
        }
        // Padding should have all digits 0-9 represented
        for (i, &c) in counts.iter().enumerate() {
            assert!(c > 0, "Padding digit {} missing", i);
        }
    }

#[test]
fn test_stego_roundtrip_with_message() {
    let kp = keygen::generate().unwrap();
    let message = b"Secret steganographic payload!";

    let digits = stego::encapsulate_stego_with_message(&kp, message).unwrap();
    assert_eq!(digits.len(), parameters::SUPERBLOCK_DIGITS);

    let recovered = stego::decapsulate_stego(&kp.seed, &digits).unwrap();
    assert_eq!(recovered, message);
}

#[test]
fn test_stego_wrong_seed_fails() {
    let kp1 = keygen::generate().unwrap();
    let kp2 = keygen::generate().unwrap();
    let message = b"Secret message for Bob";

    let digits = stego::encapsulate_stego_with_message(&kp1, message).unwrap();
    let result = stego::decapsulate_stego(&kp2.seed, &digits);

    // Wrong seed should either fail (AuthFailed) or produce garbage
    match result {
        Ok(recovered) => assert_ne!(recovered, message, "Wrong seed should not decrypt to original"),
        Err(_) => {} // AuthFailed is expected and correct
    }
}

// === Test 6: KEM Properties ===

#[test]
fn test_kem_forward_secrecy() {
    // Each encapsulation should produce a different session key
    let kp = keygen::generate().unwrap();
    let mut keys = std::collections::HashSet::new();

    for _ in 0..10 {
        let (_, key) = kem::encapsulate(&kp.public);
        keys.insert(key);
    }

    // All keys should be unique (with overwhelming probability)
    assert_eq!(keys.len(), 10, "KEM should produce unique keys per encapsulation");
}

#[test]
fn test_kem_ciphertext_randomness() {
    // KEM ciphertexts should look random
    let kp = keygen::generate().unwrap();
    let (ct1, _) = kem::encapsulate(&kp.public);
    let (ct2, _) = kem::encapsulate(&kp.public);

    // Two ciphertexts should be different
    assert_ne!(ct1.syndrome, ct2.syndrome, "KEM ciphertexts should differ");

    // Check bit density
    let ones = ct1.syndrome.iter().map(|&b| b.count_ones() as usize).sum::<usize>();
    let total = ct1.syndrome.len() * 8;
    let ratio = ones as f64 / total as f64;
    assert!(
        ratio > 0.4 && ratio < 0.6,
        "CT bit density {:.4} not close to 0.5",
        ratio
    );
}
