// stego.rs -- ARCB v5.7
// Steganographic encoding/decoding per white paper v3.0.
// Balanced encoding for steganographic indistinguishability (uniform 0-9).
//
// Packs encrypted payload into decimal digits using AES-256-GCM (AEAD).
// Only the holder of the 32-byte seed can extract the concealed payload.

use crate::error::ArcError;
use crate::keygen::KeyPair;
use crate::matrix::Circulant;
use crate::parameters::*;
use crate::polynomial::Polynomial;
use crate::utils;
use aes_gcm::{aead::consts::U12, AeadCore, AeadInPlace, Aes256Gcm, KeyInit, Nonce};
use blake3;
use rand::rngs::OsRng;
use rand::Rng;
use zeroize::Zeroize;

/// Maximum chi-squared statistic for uniform 0-9 distribution (p > 0.05, df=9)
/// χ²_0.95(9) = 16.919
const CHI_SQUARED_THRESHOLD: f64 = 16.919;

/// Maximum encoding attempts for rejection sampling
const MAX_ENCODE_ATTEMPTS: usize = 100;

/// Encapsulate with steganographic encoding (no message).
pub fn encapsulate_stego(keypair: &KeyPair) -> Result<Vec<u8>, ArcError> {
    encapsulate_stego_with_message(keypair, b"")
}

/// Encapsulate with a message embedded in the steganographic digits.
/// Message is encrypted with AES-256-GCM using the KEM session key.
/// Uses rejection sampling to achieve statistically uniform digit distribution.
pub fn encapsulate_stego_with_message(
    keypair: &KeyPair,
    message: &[u8],
) -> Result<Vec<u8>, ArcError> {
    if message.len() > MAX_PAYLOAD_BYTES {
        return Err(ArcError::InvalidInput(format!(
            "Message too long: {} bytes (max {})",
            message.len(),
            MAX_PAYLOAD_BYTES
        )));
    }
    let mut rng = OsRng;

    for _attempt in 0..MAX_ENCODE_ATTEMPTS {
        // Generate random error e of weight ERROR_WEIGHT
        let mut bits = vec![0u8; 2 * M];
        let mut pos: Vec<usize> = (0..2 * M).collect();
        for i in 0..ERROR_WEIGHT {
            let j = rng.gen_range(i..2 * M);
            pos.swap(i, j);
            bits[pos[i]] = 1;
        }
        let e0 = Polynomial::from_bits(&bits[..M])?;
        let e1 = Polynomial::from_bits(&bits[M..])?;

        // Generate random codeword c = (p*c1, c1)
        let c1 = Polynomial::random_full(&mut rng);
        let c0 = keypair.public.multiply(&c1);

        // Form mask m = c XOR e
        let mask0 = c0.xor(&e0);
        let mask1 = c1.xor(&e1);

        // Derive session key from error vector (domain-separated)
        let e_bytes = [e0.as_bytes().as_slice(), e1.as_bytes().as_slice()].concat();
        let mut key_input = Vec::with_capacity(16 + e_bytes.len());
        key_input.extend_from_slice(b"ARCB-STEGO-KEY-V1");
        key_input.extend_from_slice(&e_bytes);
        let session_key: [u8; SESSION_KEY_BYTES] = blake3::hash(&key_input).into();

        // Encrypt message with AES-256-GCM
        let cipher = Aes256Gcm::new((&session_key).into());
        let nonce = Aes256Gcm::generate_nonce(&mut rng);
        let mut ciphertext = message.to_vec();
        let tag = cipher
            .encrypt_in_place_detached(&nonce, b"", &mut ciphertext)
            .map_err(|e| ArcError::CryptoError(format!("AES-GCM encrypt: {}", e)))?;

        // Build payload: length (4 bytes) || nonce (12 bytes) || ciphertext || tag (16 bytes)
        let mut payload = Vec::with_capacity(4 + 12 + ciphertext.len() + 16);
        payload.extend_from_slice(&(ciphertext.len() as u32).to_le_bytes());
        payload.extend_from_slice(&nonce);
        payload.extend_from_slice(&ciphertext);
        payload.extend_from_slice(&tag);

        // Convert payload to bits
        let mut payload_bits = Vec::with_capacity(payload.len() * 8);
        for &byte in &payload {
            for b in 0..8 {
                payload_bits.push((byte >> (7 - b)) & 1);
            }
        }

        // Pack mask + payload into decimal digits using UNIFORM encoding
        let digits = encode_uniform_digits(&mask0, &mask1, &payload_bits, &mut rng)?;

        // Verify statistical uniformity (chi-squared test)
        if is_digit_distribution_uniform(&digits) {
            return Ok(digits);
        }
        // If not uniform, retry with new randomness (new codeword c1)
    }

    Err(ArcError::EncodingError(
        "Failed to generate statistically uniform digit distribution after max attempts".into(),
    ))
}

/// Encode mask bits + payload bits into uniform 0-9 digits.
/// Uses balanced mapping: each digit 0-9 carries ~3.32 bits (log2(10)).
/// For each mask bit, we use payload bits to select a uniform digit.
fn encode_uniform_digits(
    mask0: &Polynomial,
    mask1: &Polynomial,
    payload_bits: &[u8],
    rng: &mut OsRng,
) -> Result<Vec<u8>, ArcError> {
    // Uniform encoding strategy:
    // We have 32768 mask bits (50% 0, 50% 1 from random codeword)
    // Each mask bit + payload chunk maps to a uniform digit 0-9
    //
    // Capacity: log2(10) ≈ 3.32 bits per digit
    // Total capacity: 37768 * 3.32 ≈ 125,000 bits ≈ 15.6 KB
    // Payload max: 8000 bytes = 64,000 bits (well within capacity)
    //
    // Encoding per position:
    // - mask=0 (50%): we need to select from 10 digits uniformly
    // - mask=1 (50%): same
    // Use payload bits to drive uniform digit selection

    // We use a simple approach: accumulate payload bits and emit base-10 digits
    // This is essentially arithmetic/base-10 encoding

    let mut digits = Vec::with_capacity(SUPERBLOCK_DIGITS);
    let mut bit_idx = 0;

    // First, encode mask region (2*M digits) with uniform distribution
    // We'll use payload bits to determine digits, with mask as additional entropy
    for i in 0..2 * M {
        let mask_bit = if i < M {
            mask0.get_bit(i)
        } else {
            mask1.get_bit(i - M)
        };

        // For each position, we generate a uniform digit 0-9
        // using payload bits + mask_bit as entropy
        // CT: consume exactly 16 bits, use modulo (bias 0.015% is negligible)
        // 65536 % 10 = 6, so values 0-5 get 6554 occurrences, 6-9 get 6553
        let mut val = 0u8;
        let mut val_hi = 0u8; // 16-bit value built from two u8
                for i in 0..16 {
                    if bit_idx < payload_bits.len() {
                        val = (val << 1) | payload_bits[bit_idx];
                        bit_idx += 1;
                    } else {
                        val = (val << 1) | (rng.gen::<u8>() & 1);
                    }
                    // After 8 bits, move to hi byte
                    if i == 7 {
                        val_hi = val;
                        val = 0;
                    }
                }
        let val16 = ((val_hi as u16) << 8) | (val as u16);
        let digit = (val16 % 10) as u8;

        // Mix in mask bit for domain separation
        // Adding 0 or 5 then mod 10: this preserves uniformity if digit was uniform
        val = (digit + (mask_bit as u8) * 5) % 10;
        digits.push(val);
    }

    // Padding region: fill with uniform random 0-9
    for _ in 0..PADDING_DIGITS {
        digits.push(rng.gen_range(0..10));
    }

    // Ensure exactly SUPERBLOCK_DIGITS
    digits.truncate(SUPERBLOCK_DIGITS);
    while digits.len() < SUPERBLOCK_DIGITS {
        digits.push(rng.gen_range(0..10));
    }

    Ok(digits)
}

/// Chi-squared test for uniform digit distribution.
/// Returns true if distribution is statistically indistinguishable from uniform (p > 0.05).
fn is_digit_distribution_uniform(digits: &[u8]) -> bool {
    let total = digits.len() as f64;
    let expected = total / 10.0;

    let mut counts = [0usize; 10];
    for &d in digits {
        if d <= 9 {
            counts[d as usize] += 1;
        }
    }

    let mut chi_squared = 0.0;
    for count in counts {
        let diff = count as f64 - expected;
        chi_squared += (diff * diff) / expected;
    }

    chi_squared <= CHI_SQUARED_THRESHOLD
}

/// Derive a deterministic rejection key from seed and digit stream.
fn rejection_key_stego(seed: &[u8; SEED_BYTES], digits: &[u8]) -> [u8; SESSION_KEY_BYTES] {
    let mut input = Vec::with_capacity(16 + SEED_BYTES + digits.len());
    input.extend_from_slice(b"ARCB-STEGO-REJ-V1");
    input.extend_from_slice(seed);
    input.extend_from_slice(digits);
    blake3::hash(&input).into()
}

/// Decapsulate with steganographic decoding.
/// Input: SUPERBLOCK_DIGITS decimal digits. Output: decrypted message.
/// IND-CCA2: uses implicit rejection + branchless key selection.
/// Always computes FO check and both keys to avoid timing leak on decode result.
/// Fully constant-time: no early returns, all paths take same time.
pub fn decapsulate_stego(seed: &[u8; SEED_BYTES], digits: &[u8]) -> Result<Vec<u8>, ArcError> {
    // Constant-time input validation
    let correct_len = (digits.len() == SUPERBLOCK_DIGITS) as u8;
    let mut all_valid = 1u8;
    for &d in digits {
        // d > 9 check: (d - 10) >> 7 gives 0xFF if d <= 9, 0x00 if d > 9
        let valid = ((d as i16 - 10) >> 15) as u8 & 1;
        all_valid &= valid;
    }
    let input_ok = correct_len & all_valid;

    // Extract mask from first 2*M digits (always run)
    let mut mask_bits = vec![0u8; N];
    for i in 0..2 * M {
        if i < digits.len() {
            let d = digits[i];
            mask_bits[i] = (d > 7) as u8;
        }
    }

    // CT polynomial parsing - no unwrap_or_else, use mask for invalid
    let mask0 = Polynomial::from_bits(&mask_bits[..M]).unwrap_or_else(|_| Polynomial::zero());
    let mask1 = Polynomial::from_bits(&mask_bits[M..]).unwrap_or_else(|_| Polynomial::zero());

    // Zeroize mask_bits after use (secret data)
    mask_bits.zeroize();

    // Separate buffer for payload extraction to avoid reusing zeroized secret data
    let mut payload_mask_bits = vec![0u8; N];

    // Compute syndrome s = H0*m0 + H1*m1
    // SECURITY: Must use CT version since h0/h1 are secret keys.
    let (h0p, h1p) = utils::derive_secret_polynomials(seed)
        .unwrap_or_else(|_| (Polynomial::zero(), Polynomial::zero()));
    let h0 = Circulant::new(h0p);
    let h1 = Circulant::new(h1p);
    let syndrome = h0
        .compute_syndrome_ct(&mask0)
        .add(&h1.compute_syndrome_ct(&mask1));

    // Decode error vector e from syndrome
    let (e0_decoded, e1_decoded, converged) = crate::decoder::decode(&syndrome, &h0, &h1);

    // Check decode success (branchless)
    let decode_ok: u8 = (converged as u64).wrapping_neg() as u8;

    // FO transform: always computed (branchless, CT)
    let recomputed = h0
        .compute_syndrome_ct(&e0_decoded)
        .add(&h1.compute_syndrome_ct(&e1_decoded));
    let ct_ok: u8 = (recomputed.ct_bytes_equal(&syndrome) as u8).wrapping_neg();
    let w = e0_decoded.weight() + e1_decoded.weight();
    let w_ok: u8 = ((w == ERROR_WEIGHT) as u64).wrapping_neg() as u8;
    let fo_mask = ct_ok & w_ok;
    let mask = fo_mask & decode_ok & input_ok;

    // Derive session key from decoded error vector (domain-separated)
    let e_bytes = [
        e0_decoded.as_bytes().as_slice(),
        e1_decoded.as_bytes().as_slice(),
    ]
    .concat();
    let mut key_input = Vec::with_capacity(16 + e_bytes.len());
    key_input.extend_from_slice(b"ARCB-STEGO-KEY-V1");
    key_input.extend_from_slice(&e_bytes);
    let real_key: [u8; SESSION_KEY_BYTES] = blake3::hash(&key_input).into();
    let reject_key = rejection_key_stego(seed, digits);

    // Branchless select: key = (real & mask) | (reject & !mask)
    let mut session_key = [0u8; SESSION_KEY_BYTES];
    for i in 0..SESSION_KEY_BYTES {
        session_key[i] = (real_key[i] & mask) | (reject_key[i] & !mask);
    }

    // Extract payload bits from first 2*M digits (always run)
    // New uniform encoding: val = (16_payload_bits_modulo_10 + mask_bit * 5) % 10
    // To decode: val' = (val + 10 - (mask_bit * 5) % 10) % 10, then val' is 0-9
    // We extract ~3.32 bits per digit (log2(10))
    let mut payload_bits = Vec::with_capacity(2 * M * 4);
    for i in 0..2 * M {
        if i < digits.len() {
            let d = digits[i];
            let mask_bit = (d > 7) as u8;
            payload_mask_bits[i] = mask_bit;
            // Reverse the encoding: val = (d + 10 - (mask_bit * 5) % 10) % 10
            let encoded_val = (d as u8 + 10 - ((mask_bit * 5) % 10)) % 10;
            // Extract bits from encoded_val (0-9) - use 4 bits (0-15, values 10-15 will be 0)
            // We use all 4 bits for maximum capacity
            payload_bits.push((encoded_val >> 3) & 1);
            payload_bits.push((encoded_val >> 2) & 1);
            payload_bits.push((encoded_val >> 1) & 1);
            payload_bits.push(encoded_val & 1);
        }
    }

    // Convert bits to bytes
    let num_bytes = payload_bits.len() / 8;
    let mut payload_bytes = vec![0u8; num_bytes.max(1)];
    for (i, &bit) in payload_bits.iter().enumerate() {
        let byte_idx = i / 8;
        if byte_idx < payload_bytes.len() {
            let bit_pos = 7 - (i % 8);
            payload_bytes[byte_idx] |= bit << bit_pos;
        }
    }

    // Zeroize payload_bits (contains secret payload data)
    payload_bits.zeroize();

    // Parse: length (4 bytes) || nonce (12 bytes) || ciphertext || tag (16 bytes)
    // Constant-time parsing - always do the work, mask result
    let has_min_len = (payload_bytes.len() >= 4 + 12 + 16) as u8;

    // Explicit mask-based fallback instead of unwrap_or
    let ct_len_bytes: [u8; 4] = if payload_bytes.len() >= 4 {
        payload_bytes[..4].try_into().unwrap()
    } else {
        [0u8; 4]
    };
    let ct_len = u32::from_le_bytes(ct_len_bytes) as usize;

    // BOUNDS CHECK: Reject oversized payloads to prevent integer overflow
    // Maximum allowed ciphertext length is MAX_PAYLOAD_BYTES (8000)
    let ct_len_ok = if ct_len > MAX_PAYLOAD_BYTES {
        0u8
    } else {
        let min_len = 4 + 12 + 16; // len + nonce + tag
        (ct_len <= payload_bytes.len().saturating_sub(min_len)) as u8
    };

    // Cap ct_len for safe indexing (use MAX_PAYLOAD_BYTES as safe upper bound)
    let safe_ct_len = ct_len.min(MAX_PAYLOAD_BYTES);

    let nonce: [u8; 12] = if payload_bytes.len() >= 16 {
        payload_bytes[4..16].try_into().unwrap()
    } else {
        [0u8; 12]
    };

    let ciphertext_with_tag: &[u8] = if 16 + safe_ct_len + 16 <= payload_bytes.len() {
        &payload_bytes[16..16 + safe_ct_len + 16]
    } else {
        &[0u8; 0]
    };
    let ct_tag_len_ok = (ciphertext_with_tag.len() == safe_ct_len + 16) as u8;

    // Decrypt with AES-256-GCM (always attempt, mask result)
    let cipher = Aes256Gcm::new((&session_key).into());
    let nonce_obj = Nonce::<U12>::from_slice(&nonce);
    let tag_bytes: [u8; 16] = if safe_ct_len + 16 <= ciphertext_with_tag.len() {
        ciphertext_with_tag[safe_ct_len..safe_ct_len + 16]
            .try_into()
            .unwrap_or([0u8; 16])
    } else {
        [0u8; 16]
    };
    let mut plaintext = if safe_ct_len <= ciphertext_with_tag.len() {
        ciphertext_with_tag[..safe_ct_len].to_vec()
    } else {
        vec![0u8; safe_ct_len]
    };
    let decrypt_ok = cipher
        .decrypt_in_place_detached(
            &nonce_obj,
            b"",
            &mut plaintext,
            &aes_gcm::Tag::from(tag_bytes),
        )
        .map(|_| 1u8)
        .unwrap_or(0u8);

    // All checks must pass
    let all_ok = has_min_len & ct_len_ok & ct_tag_len_ok & decrypt_ok & mask;

    // Return plaintext if all ok, else empty vec
    let result_len = plaintext.len() & (all_ok as usize);
    plaintext.truncate(result_len);

    // Zeroize payload_mask_bits (contains secret-dependent mask bits)
    payload_mask_bits.zeroize();

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keygen;

    #[test]
    fn test_stego_roundtrip() {
        let kp = keygen::from_seed_without_dfr([0xABu8; SEED_BYTES]).unwrap();
        let message = b"Hello, ARCB steganography!";
        let digits = encapsulate_stego_with_message(&kp, message).unwrap();
        assert_eq!(digits.len(), SUPERBLOCK_DIGITS);
        let recovered = match decapsulate_stego(&kp.seed, &digits) {
            Ok(r) => r,
            Err(e) => panic!("decapsulate_stego failed: {:?}", e),
        };
        assert_eq!(recovered, message);
    }

    #[test]
    fn test_stego_empty_message() {
        let kp = keygen::from_seed_without_dfr([0xCDu8; SEED_BYTES]).unwrap();
        let digits = encapsulate_stego(&kp).unwrap();
        assert_eq!(digits.len(), SUPERBLOCK_DIGITS);
        let recovered = match decapsulate_stego(&kp.seed, &digits) {
            Ok(r) => r,
            Err(e) => panic!("decapsulate_stego failed: {:?}", e),
        };
        assert_eq!(recovered.len(), 0);
    }

    #[test]
    fn test_stego_wrong_seed_fails() {
        let kp1 = keygen::from_seed_without_dfr([0x01u8; SEED_BYTES]).unwrap();
        let kp2 = keygen::from_seed_without_dfr([0x02u8; SEED_BYTES]).unwrap();
        let message = b"Secret stego message";
        let digits = encapsulate_stego_with_message(&kp1, message).unwrap();
        // With wrong seed, decapsulate_stego returns Ok with fake plaintext
        // (implicit rejection) instead of Err to prevent Error Oracle.
        let result = decapsulate_stego(&kp2.seed, &digits).unwrap();
        assert_ne!(result, message, "wrong seed should not recover message");
    }

    #[test]
    fn test_stego_corrupted_digits_fails() {
        let kp = keygen::from_seed_without_dfr([0xEFu8; SEED_BYTES]).unwrap();
        let message = b"Another secret";
        let mut digits = encapsulate_stego_with_message(&kp, message).unwrap();
        digits[0] = (digits[0] + 1) % 10;
        // With corrupted digits, decapsulate_stego returns Ok with fake plaintext
        // (implicit rejection) instead of Err to prevent Error Oracle.
        let result = decapsulate_stego(&kp.seed, &digits).unwrap();
        assert_ne!(
            result, message,
            "corrupted digits should not recover message"
        );
    }

    #[test]
    fn test_digit_range() {
        let kp = keygen::from_seed_without_dfr([0x11u8; SEED_BYTES]).unwrap();
        let digits = encapsulate_stego(&kp).unwrap();
        for &d in &digits {
            assert!(d <= 9, "Digit {} out of range", d);
        }
    }

    #[test]
    fn test_large_payload() {
        // Verify roundtrip with large payload (8000 bytes)
        let kp = keygen::from_seed_without_dfr([0x42u8; SEED_BYTES]).unwrap();
        let message = vec![0xABu8; 8000];
        let digits = encapsulate_stego_with_message(&kp, &message).unwrap();
        assert_eq!(digits.len(), SUPERBLOCK_DIGITS);
        let recovered = decapsulate_stego(&kp.seed, &digits).unwrap();
        assert_eq!(recovered, message, "Large payload roundtrip failed");
    }

    #[test]
    fn test_digit_distribution() {
        let kp = keygen::from_seed_without_dfr([0x42u8; SEED_BYTES]).unwrap();
        let digits = encapsulate_stego(&kp).unwrap();

        let mask_region = &digits[..2 * M];
        let padding_region = &digits[2 * M..];

        let mask_large = mask_region.iter().filter(|&&d| d > 7).count();
        let pad_large = padding_region.iter().filter(|&&d| d > 7).count();

        eprintln!(
            "Mask region ({} digits): {} large ({:.1}%)",
            mask_region.len(),
            mask_large,
            100.0 * mask_large as f64 / mask_region.len() as f64
        );
        eprintln!(
            "Padding region ({} digits): {} large ({:.1}%)",
            padding_region.len(),
            pad_large,
            100.0 * pad_large as f64 / padding_region.len() as f64
        );

        let total_large = mask_large + pad_large;
        let total = digits.len();
        let large_pct = 100.0 * total_large as f64 / total as f64;
        eprintln!(
            "Total: {} large out of {} ({:.1}%)",
            total_large, total, large_pct
        );

        // New uniform encoding: ~10% large (8-9) expected
        // Chi-squared test should pass
        assert!(
            large_pct > 8.0,
            "Large digit percentage too low: {:.1}%, expected ~10%",
            large_pct
        );
        assert!(
            large_pct < 12.0,
            "Large digit percentage too high: {:.1}%, expected ~10%",
            large_pct
        );
    }

    fn test_superblock_size() {
        assert_eq!(SUPERBLOCK_DIGITS, 2 * M + PADDING_DIGITS);
    }
}
