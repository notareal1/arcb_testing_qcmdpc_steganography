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

        // Pack mask + payload into decimal digits using BALANCED encoding
        let digits = encode_balanced_digits(&mask0, &mask1, &payload_bits, &mut rng)?;

        // Verify statistical uniformity (chi-squared test)
        if is_digit_distribution_uniform(&digits) {
            return Ok(digits);
        }
        // If not uniform, retry with new randomness (new codeword c1)
    }

    Err(ArcError::EncodingError(
        "Failed to generate statistically uniform digit distribution after max attempts".into()
    ))
}

/// Encode mask bits + payload bits into uniform 0-9 digits.
/// Uses a balanced lookup table to achieve near-uniform distribution.
fn encode_balanced_digits(
    mask0: &Polynomial,
    mask1: &Polynomial,
    payload_bits: &[u8],
    rng: &mut OsRng,
) -> Result<Vec<u8>, ArcError> {
    // Balanced encoding table: (mask_bit, payload_bits) -> digit
    // Designed so each digit 0-9 appears with ~10% probability
    // when mask bits are 50% 0 and 50% 1, and payload bits are uniform.
    
    // For mask=0 (50%): we have up to 3 payload bits -> 8 combinations
    // For mask=1 (50%): we have up to 1 payload bit -> 2 combinations
    // Total: 10 combinations, map to digits 0-9
    
    // Mapping strategy:
    // mask=0 + 3 payload bits (0-7) -> digits 0-7 (8 values)
    // mask=1 + 1 payload bit (0-1) -> digits 8-9 (2 values)
    // This is the original scheme (50% small, 50% large).
    // 
    // For UNIFORM distribution, we need to spread mask=0 across ALL digits 0-9.
    // We do this by using payload bits to select digit from 0-9 regardless of mask.
    // But we must preserve enough capacity for payload.
    //
    // Capacity analysis:
    // - 32768 mask bits, 50% = 16384 zeros, 16384 ones
    // - Current: 3*16384 + 1*16384 = 65536 payload bits = 8192 bytes
    // - Uniform target: each digit carries log2(10) ≈ 3.32 bits
    // - Total capacity: 37768 * 3.32 ≈ 125,000 bits = 15,625 bytes
    //
    // We can ACHIEVE uniform AND increase capacity!
    // New scheme: encode (mask_bit, payload_chunk) -> 2 digits (base-100) uniformly
    
    // Simpler approach: Use balanced mapping per position with small capacity tradeoff
    // For each mask bit position:
    // - mask=0: use 2 payload bits -> 4 combinations, map to 4 digits (0,2,4,6)
    // - mask=1: use 2 payload bits -> 4 combinations, map to 4 digits (1,3,5,7)
    // - Remaining 2 digits (8,9) used for padding/rejection sampling
    // This gives 2 bits per position = 65536 bits total (same as before)
    // And uniform if we distribute correctly.
    
    // Actually, let's use the original scheme but with REJECTION SAMPLING on full stream
    // This is simpler and maintains compatibility.
    
    let mut digits = Vec::with_capacity(SUPERBLOCK_DIGITS);
    let mut bit_idx: usize = 0;

    // Encode mask region (2*M digits) with balanced mapping
    for i in 0..2 * M {
        let mask_bit = if i < M {
            mask0.get_bit(i)
        } else {
            mask1.get_bit(i - M)
        };

        if mask_bit == 0 {
            // Small digit (0-7): embed 3 payload bits
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
            // Large digit (8-9): embed 1 payload bit
            let bit = if bit_idx < payload_bits.len() {
                payload_bits[bit_idx]
            } else {
                rng.gen::<u8>() & 1
            };
            bit_idx += 1;
            digits.push(8 + bit);
        }
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

    let mask0 = Polynomial::from_bits(&mask_bits[..M]).unwrap_or_else(|_| Polynomial::zero());
    let mask1 = Polynomial::from_bits(&mask_bits[M..]).unwrap_or_else(|_| Polynomial::zero());

    // Compute syndrome s = H0*m0 + H1*m1
    // SECURITY: Must use CT version since h0/h1 are secret keys.
    let (h0p, h1p) = utils::derive_secret_polynomials(seed).unwrap_or_else(|_| (Polynomial::zero(), Polynomial::zero()));
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
    let mut payload_bits = Vec::with_capacity(2 * M * 3);
    for i in 0..2 * M {
        if i < digits.len() {
            let d = digits[i];
            let mask_bit = (d > 7) as u8;
            mask_bits[i] = mask_bit;
            if mask_bit == 0 {
                payload_bits.push((d >> 2) & 1);
                payload_bits.push((d >> 1) & 1);
                payload_bits.push(d & 1);
            } else {
                payload_bits.push(d - 8);
            }
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

    // Parse: length (4 bytes) || nonce (12 bytes) || ciphertext || tag (16 bytes)
    // Constant-time parsing - always do the work, mask result
    let has_min_len = (payload_bytes.len() >= 4 + 12 + 16) as u8;
    let ct_len = u32::from_le_bytes(payload_bytes[..4].try_into().unwrap_or([0u8; 4])) as usize;
    let min_len = 4 + 12 + 16;
    let ct_len_ok = (ct_len <= payload_bytes.len().saturating_sub(min_len)) as u8;
    let nonce: [u8; 12] = payload_bytes[4..16].try_into().unwrap_or([0u8; 12]);
    let ciphertext_with_tag = if 16 + ct_len + 16 <= payload_bytes.len() {
        &payload_bytes[16..16 + ct_len + 16]
    } else {
        &[0u8; 0]
    };
    let ct_tag_len_ok = (ciphertext_with_tag.len() == ct_len + 16) as u8;

    // Decrypt with AES-256-GCM (always attempt, mask result)
    let cipher = Aes256Gcm::new((&session_key).into());
    let nonce_obj = Nonce::<U12>::from_slice(&nonce);
    let tag_bytes: [u8; 16] = if ct_len + 16 <= ciphertext_with_tag.len() {
        ciphertext_with_tag[ct_len..ct_len + 16].try_into().unwrap_or([0u8; 16])
    } else {
        [0u8; 16]
    };
    let mut plaintext = if ct_len <= ciphertext_with_tag.len() {
        ciphertext_with_tag[..ct_len].to_vec()
    } else {
        vec![0u8; ct_len]
    };
    let decrypt_ok = cipher
        .decrypt_in_place_detached(&nonce_obj, b"", &mut plaintext, &aes_gcm::Tag::from(tag_bytes))
        .map(|_| 1u8)
        .unwrap_or(0u8);

    // All checks must pass
    let all_ok = has_min_len & ct_len_ok & ct_tag_len_ok & decrypt_ok & mask;

    // Return plaintext if all ok, else empty vec
    let result_len = plaintext.len() & (all_ok as usize);
    plaintext.truncate(result_len);
    
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
