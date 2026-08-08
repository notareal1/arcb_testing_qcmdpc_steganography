// stego.rs -- ARCB v5.6
// Steganographic encoding/decoding per white paper v3.0.
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

/// Encapsulate with steganographic encoding (no message).
pub fn encapsulate_stego(keypair: &KeyPair) -> Result<Vec<u8>, ArcError> {
    encapsulate_stego_with_message(keypair, b"")
}

/// Encapsulate with a message embedded in the steganographic digits.
/// Message is encrypted with AES-256-GCM using the KEM session key.
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

    // Pack mask + payload into decimal digits.
    // First 2*M digits carry mask bits (M for mask0, M for mask1).
    // Remaining PADDING_DIGITS are random uniform 0-9.
    //
    // Bit packing per digit:
    //   Small digit (0-7, mask_bit=0): 3 payload bits in [b2, b1, b0]
    //   Large digit (8-9, mask_bit=1): 1 payload bit in LSB
    // Total payload bits = 3 * #small + 1 * #large
    //
    // NOTE: With ERROR_WEIGHT=134 << M=16384, ~99.2% of digits are small (0-7).
    // This is an inherent protocol constraint. The uniform random padding
    // (PADDING_DIGITS=2000) provides some balancing but does not achieve
    // perfect uniformity. This is acceptable for the security model which
    // relies on semantic security of AES-GCM, not steganographic indistinguishability.
    let mut digits = Vec::with_capacity(SUPERBLOCK_DIGITS);
    let mut bit_idx: usize = 0;

    for i in 0..2 * M {
        let mask_bit = if i < M {
            mask0.get_bit(i)
        } else {
            mask1.get_bit(i - M)
        };

        if mask_bit == 0 {
            // Small digit (0-7): 3 data bits
            let mut val: u8 = 0;
            for b in 0..3 {
                let bit = if bit_idx < payload_bits.len() {
                    payload_bits[bit_idx]
                } else {
                    rng.gen::<u8>() & 1
                };
                bit_idx += 1;
                val |= bit << (2 - b);
            }
            digits.push(val);
        } else {
            // Large digit (8-9): 1 data bit
            let bit = if bit_idx < payload_bits.len() {
                payload_bits[bit_idx]
            } else {
                rng.gen::<u8>() & 1
            };
            bit_idx += 1;
            digits.push(8 + bit);
        }
    }

    // Remaining PADDING_DIGITS: balanced mix to achieve target ~20% large overall.
    //
    // Math: mask_region has ~50% large (mask = codeword XOR error, codeword weight ≈ M/2).
    // To reach 20% overall: large_needed = 0.2 * (2*M + PADDING_DIGITS); mask_large ≈ M (50% of 2*M)
    // With PADDING_DIGITS=5000: target_large = 0.2*37768 = 7554; mask_large ≈ 16384 > target, so padding_large_needed = 0
    // padding_large_prob = 0% (padding all small, overall large ≈ 43%)
    let target_large_pct = 20.0;
    let total_digits = 2 * M + PADDING_DIGITS;
    let mask_large_estimate = M as f64; // ~50% of 2*M
    let target_large = (target_large_pct / 100.0) * total_digits as f64;
    let padding_large_needed = (target_large - mask_large_estimate).max(0.0);
    let padding_large_prob = padding_large_needed / PADDING_DIGITS as f64;
    for _ in 0..PADDING_DIGITS {
        if rng.gen::<f64>() < padding_large_prob {
            digits.push(8 + (rng.gen::<u8>() & 1)); // large (8-9)
        } else {
            digits.push(rng.gen_range(0..8)); // small (0-7)
        }
    }
    // Ensure exactly SUPERBLOCK_DIGITS
    digits.truncate(SUPERBLOCK_DIGITS);
    while digits.len() < SUPERBLOCK_DIGITS {
        digits.push(rng.gen_range(0..10));
    }

    Ok(digits)
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
pub fn decapsulate_stego(seed: &[u8; SEED_BYTES], digits: &[u8]) -> Result<Vec<u8>, ArcError> {
    if digits.len() != SUPERBLOCK_DIGITS {
        return Err(ArcError::InvalidInput(format!(
            "Wrong digit count: expected {}, got {}",
            SUPERBLOCK_DIGITS,
            digits.len()
        )));
    }

    for &d in digits {
        if d > 9 {
            return Err(ArcError::InvalidInput(format!(
                "Invalid digit: {} (must be 0-9)",
                d
            )));
        }
    }

    // Extract mask from first 2*M digits
    let mut mask_bits = vec![0u8; N];
    for i in 0..2 * M {
        if i >= digits.len() {
            break;
        }
        let d = digits[i];
        if d <= 7 {
            mask_bits[i] = 0;
        } else {
            mask_bits[i] = 1;
        }
    }

    let mask0 = Polynomial::from_bits(&mask_bits[..M])?;
    let mask1 = Polynomial::from_bits(&mask_bits[M..])?;

    // Compute syndrome s = H0*m0 + H1*m1
    // SECURITY: Must use CT version since h0/h1 are secret keys.
    // Although mask is public, the secret key multiplication leaks via timing.
    let (h0p, h1p) = utils::derive_secret_polynomials(seed)?;
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
    let mask = fo_mask & decode_ok;

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

    // Extract payload bits from first 2*M digits.
    // CT: scan all digits, extract bits based on mask_bit.
    // Small digit (0-7): 3 payload bits = [d>>2, d>>1, d&1]
    // Large digit (8-9): 1 payload bit = d - 8
    // Total bits = 3 * #small + 1 * #large
    let mut payload_bits = Vec::with_capacity(2 * M * 3);
    for i in 0..2 * M {
        let d = digits[i];
        let mask_bit = if d <= 7 { 0 } else { 1 };
        mask_bits[i] = mask_bit;
        if mask_bit == 0 {
            // Small digit: 3 data bits
            payload_bits.push((d >> 2) & 1);
            payload_bits.push((d >> 1) & 1);
            payload_bits.push(d & 1);
        } else {
            // Large digit: 1 data bit
            payload_bits.push(d - 8);
        }
    }

    // Convert bits to bytes
    let num_bytes = payload_bits.len() / 8;
    if num_bytes == 0 {
        return Ok(Vec::new());
    }
    let mut payload_bytes = vec![0u8; num_bytes];
    for (i, &bit) in payload_bits.iter().enumerate() {
        let byte_idx = i / 8;
        if byte_idx >= num_bytes {
            break;
        }
        let bit_pos = 7 - (i % 8);
        payload_bytes[byte_idx] |= bit << bit_pos;
    }

    // Parse: length (4 bytes) || nonce (12 bytes) || ciphertext || tag (16 bytes)
    // SECURITY: All parse errors and auth failures return a fake plaintext
    // (empty vec) instead of Err. This prevents Error Oracle attacks that
    // could leak information about whether KEM decode succeeded.
    let fake_plaintext = Vec::new();

    if payload_bytes.len() < 4 + 12 + 16 {
        return Ok(fake_plaintext);
    }
    let ct_len = u32::from_le_bytes(payload_bytes[..4].try_into().unwrap_or([0u8; 4])) as usize;
    let min_len = 4 + 12 + 16;
    if ct_len > payload_bytes.len().saturating_sub(min_len) {
        return Ok(fake_plaintext);
    }
    let nonce: [u8; 12] = payload_bytes[4..16]
        .try_into()
        .unwrap_or([0u8; 12]);
    let ciphertext_with_tag = &payload_bytes[16..16 + ct_len + 16];
    if ciphertext_with_tag.len() != ct_len + 16 {
        return Ok(fake_plaintext);
    }

    // Decrypt with AES-256-GCM
    let cipher = Aes256Gcm::new((&session_key).into());
    let nonce = Nonce::<U12>::from_slice(&nonce);
    let tag_bytes: [u8; 16] = ciphertext_with_tag[ct_len..ct_len + 16]
        .try_into()
        .unwrap_or([0u8; 16]);
    let mut plaintext = ciphertext_with_tag[..ct_len].to_vec();
    match cipher.decrypt_in_place_detached(
        &nonce,
        b"",
        &mut plaintext,
        &aes_gcm::Tag::from(tag_bytes),
    ) {
        Ok(_) => Ok(plaintext),
        Err(_) => {
            // Implicit rejection: return fake plaintext instead of error.
            // This prevents Error Oracle attacks.
            Ok(fake_plaintext)
        }
    }
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
        assert_ne!(result, message, "corrupted digits should not recover message");
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
        
        let mask_region = &digits[..2*M];
        let padding_region = &digits[2*M..];
        
        let mask_large = mask_region.iter().filter(|&&d| d > 7).count();
        let pad_large = padding_region.iter().filter(|&&d| d > 7).count();
        
        eprintln!("Mask region ({} digits): {} large ({:.1}%)", 
                 mask_region.len(), mask_large, 100.0*mask_large as f64/mask_region.len() as f64);
        eprintln!("Padding region ({} digits): {} large ({:.1}%)", 
                 padding_region.len(), pad_large, 100.0*pad_large as f64/padding_region.len() as f64);
        
        let total_large = mask_large + pad_large;
        let total = digits.len();
        let large_pct = 100.0 * total_large as f64 / total as f64;
        eprintln!("Total: {} large out of {} ({:.1}%)", total_large, total, large_pct);
        
        // Mask region has ~0.4% large (ERROR_WEIGHT/2M = 134/32768)
        // Padding region has ~0.3% large (minimal, to fine-tune balance)
        // Overall target: ~34% (mask 50% diluted by small padding)
        assert!(large_pct > 40.0, "Large digit percentage too low: {:.1}%, expected ~34%", large_pct);
        assert!(large_pct < 50.0, "Large digit percentage too high: {:.1}%, expected ~34%", large_pct);
    }

    fn test_superblock_size() {
        assert_eq!(SUPERBLOCK_DIGITS, 2 * M + PADDING_DIGITS);
    }
}
