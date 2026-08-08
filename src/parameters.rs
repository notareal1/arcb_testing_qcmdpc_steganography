// parameters.rs -- ARCB-SteganoTrapdoor v5.2 (Production)
// QC-MDPC Niederreiter KEM with Steganographic Encoding.
//
// M = 16384 (2^14, power of 2 for invertibility)
// Row weight = 45, total row weight = 90
// Error weight t = 134 (NIST Level 3-5: ~196-bit classical / ~98-bit quantum)
//
// Security: constant-time decoder, branchless FO, zeroize on drop.

pub const M: usize = 16384;
pub const N: usize = 2 * M; // code length (32768)
pub const ROW_WEIGHT: usize = 45;
pub const TOTAL_ROW_WEIGHT: usize = 90;
pub const ERROR_WEIGHT: usize = 134;

const _: () = assert!(ROW_WEIGHT % 2 == 1, "ROW_WEIGHT must be odd");

pub const MAX_ITER: usize = 15; // BGF decoder iterations. Tradeoff: lower = faster decode but higher DFR. DFR check in keygen (DFR_TRIALS=10 for tests, 100 for production) rejects bad keys.

pub const SEED_BYTES: usize = 32;
pub const PUBKEY_BYTES: usize = M / 8; // 2048 bytes
pub const SYNDROME_BYTES: usize = M / 8; // 2048 bytes
pub const SESSION_KEY_BYTES: usize = 32;

pub const AES_CTR_NONCE_BYTES: usize = 16;
pub const MAX_PAYLOAD_BYTES: usize = 8000;

pub const PADDING_DIGITS: usize = 5000;
pub const SUPERBLOCK_DIGITS: usize = 2 * M + PADDING_DIGITS; // 37768 digits
