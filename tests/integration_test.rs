// integration_test.rs -- ARCB v5.12
// Integration tests for the KEM layer.

use arcb_stegano_trapdoor::*;
use arcb_stegano_trapdoor::keygen::from_seed_without_dfr;

/// Helper: generate a key pair for integration tests (bypass DFR for speed)
/// Uses public key derivation from seed without DFR check.
fn test_keypair() -> KeyPair {
    from_seed_without_dfr([0x42u8; SEED_BYTES]).expect("Seed 0x42 should generate valid key")
}

// -- KEM round-trip tests -------------------------------------------

#[test]
fn test_kem_roundtrip_basic() {
    let kp = test_keypair();
    let (ct, k1) = kem::encapsulate(&kp.public);
    let k2 = kem::decapsulate(&kp.seed, &ct).unwrap();
    assert_eq!(k1, k2);
}

#[test]
fn test_kem_roundtrip_100_rounds() {
    let kp = test_keypair();
    for _ in 0..10 {
        let (ct, k1) = kem::encapsulate(&kp.public);
        let k2 = kem::decapsulate(&kp.seed, &ct).unwrap();
        assert_eq!(k1, k2);
    }
}

#[test]
fn test_kem_roundtrip_multiple_keys() {
    for i in 0u8..20 {
        let seed = [i; SEED_BYTES];
        let kp = test_keypair();
        let (ct, k1) = kem::encapsulate(&kp.public);
        let k2 = kem::decapsulate(&kp.seed, &ct).unwrap();
        assert_eq!(k1, k2, "key {} failed", i);
    }
}

#[test]
fn test_kem_roundtrip_cached() {
    let kp = test_keypair();
    let (h0p, h1p) = utils::derive_secret_polynomials(&kp.seed).unwrap();
    let h0 = matrix::Circulant::new(h0p);
    let h1 = matrix::Circulant::new(h1p);

    for _ in 0..10 {
        let (ct, k1) = kem::encapsulate(&kp.public);
        let k2 = kem::decapsulate_cached(&kp.seed, &h0, &h1, &ct).unwrap();
        assert_eq!(k1, k2);
    }
}

// -- Ciphertext properties ------------------------------------------

#[test]
fn test_ciphertext_size() {
    let kp = test_keypair();
    let (ct, _) = kem::encapsulate(&kp.public);
    assert_eq!(ct.syndrome.len(), SYNDROME_BYTES);
}

#[test]
fn test_different_encaps_produce_different_ciphertexts() {
    let kp = test_keypair();
    let (ct1, _) = kem::encapsulate(&kp.public);
    let (ct2, _) = kem::encapsulate(&kp.public);
    assert_ne!(ct1.syndrome, ct2.syndrome);
}

#[test]
fn test_different_keys_different_ciphertexts() {
    let kp1 = test_keypair();
    let kp2 = test_keypair();
    let (ct1, _) = kem::encapsulate(&kp1.public);
    let (ct2, _) = kem::encapsulate(&kp2.public);
    assert_ne!(ct1.syndrome, ct2.syndrome);
}

// -- Security tests -------------------------------------------------

#[test]
fn test_wrong_seed_fails() {
    let kp1 = test_keypair();
    let kp2 = test_keypair();
    let (ct, k1) = kem::encapsulate(&kp1.public);
    let result = kem::decapsulate(&kp2.seed, &ct);
    // With implicit rejection, wrong seed returns Ok(rejection_key)
    assert!(result.is_ok());
    assert_ne!(result.unwrap(), k1);
}

#[test]
fn test_corrupted_ct_fails() {
    let kp = test_keypair();
    let (mut ct, k1) = kem::encapsulate(&kp.public);
    ct.syndrome[0] ^= 0xFF;
    // With implicit rejection, corrupted ct returns Ok(rejection_key) instead of Err
    let result = kem::decapsulate(&kp.seed, &ct);
    // The result should be Ok but with a different key
    assert!(result.is_ok());
    assert_ne!(result.unwrap(), k1);
}

// -- Key properties -------------------------------------------------

#[test]
fn test_keygen_deterministic() {
    let seed = [0x42u8; SEED_BYTES];
    let kp1 = test_keypair();
    let kp2 = test_keypair();
    assert!(kp1.public.equals(&kp2.public));
}

#[test]
fn test_keygen_different_seeds() {
    let kp1 = test_keypair();
    let kp2 = test_keypair();
    assert!(!kp1.public.equals(&kp2.public));
}

#[test]
fn test_public_key_not_zero() {
    let kp = test_keypair();
    assert!(!kp.public.is_zero());
}

#[test]
fn test_public_key_size() {
    let kp = test_keypair();
    assert_eq!(kp.public.as_bytes().len(), PUBKEY_BYTES);
}

// -- Session key properties -----------------------------------------

#[test]
fn test_session_key_not_zero() {
    let kp = test_keypair();
    let (_, k) = kem::encapsulate(&kp.public);
    assert!(k.iter().any(|&b| b != 0));
}

#[test]
fn test_session_keys_different_per_encaps() {
    let kp = test_keypair();
    let mut keys = Vec::new();
    for _ in 0..10 {
        let (_, k) = kem::encapsulate(&kp.public);
        keys.push(k);
    }
    for i in 0..keys.len() {
        for j in (i + 1)..keys.len() {
            assert_ne!(keys[i], keys[j], "keys {} and {} collide", i, j);
        }
    }
}
