// parameters.rs -- ARCB-SteganoTrapdoor v5.14 (Production)
// QC-MDPC Niederreiter KEM with Steganographic Encoding.
//
// M = 16384 (2^14, power of 2 for invertibility in GF(2)[x]/(x^M - 1))
// Row weight = 45, total row weight = 90 (odd weight ensures all polys invertible)
// Error weight t = 134 (NIST Level 3-5: ~196-bit classical / ~98-bit quantum)
//
// Security: constant-time decoder, branchless FO, zeroize on drop.
//
// Magic numbers justification:
// - M = 16384 = 2^14: Power of 2 ensures x^M - 1 = (x-1)^M in GF(2), simplifies inversion
// - ROW_WEIGHT = 45: Odd weight guarantees invertibility per [Bernstein et al., BIKE spec]
// - ERROR_WEIGHT = 134: DFR ~ 2^-64 with this weight, fits NIST L3-5
// - MAX_ITER = 15: BGF decoder iterations. Tradeoff: lower = faster decode but higher DFR.
//   Keygen rejects bad keys (DFR check with trials).
// - T_BLACK_INIT = 40: Initial black threshold (syndrome weight > 40 → definite error bit)
// - T_BLACK_FINAL = 20: Final black threshold (adaptive decrease over iterations)
// - T_GRAY_INIT = 30: Initial gray threshold (suspect but not definite)
// - T_GRAY_FINAL = 12: Final gray threshold
// - GRAY_COUNT_MIN = 2: Minimum gray count before flipping
// - BLACK_ONLY_ITERS = 7: First 7 iterations only black flips, then gray enabled
// - CHI_SQUARED_THRESHOLD = 16.919: χ²_0.95(9) - uniform digit distribution test (p > 0.05, df=9)
// - DFR_TRIALS = 270: Keygen DFR trials. Statistical confidence for DFR < 2^-128
// - PADDING_DIGITS = 5000: Stego padding region for uniform digit distribution

pub const M: usize = 16384;
pub const N: usize = 2 * M; // code length (32768)
pub const ROW_WEIGHT: usize = 45;
pub const TOTAL_ROW_WEIGHT: usize = 90;
pub const ERROR_WEIGHT: usize = 134;

const _: () = assert!(ROW_WEIGHT % 2 == 1, "ROW_WEIGHT must be odd");

// BGF Decoder thresholds (justified by QC-MDPC syndrome weight distribution):
// Initial black threshold: syndrome weight where a bit is definitely in error
pub const T_BLACK_INIT: u8 = 40;
// Final black threshold: decreased adaptively over MAX_ITER iterations
pub const T_BLACK_FINAL: u8 = 20;
// Gray thresholds for uncertain bits
pub const T_GRAY_INIT: u8 = 30;
pub const T_GRAY_FINAL: u8 = 12;
// Minimum gray count before considering a bit for flip
pub const GRAY_COUNT_MIN: u16 = 2;
// Number of iterations with only black flips (no gray)
pub const BLACK_ONLY_ITERS: usize = 7;

// Maximum BGF decoder iterations (15 = balance speed vs DFR)
pub const MAX_ITER: usize = 15;

pub const SEED_BYTES: usize = 32;
pub const PUBKEY_BYTES: usize = M / 8; // 2048 bytes
pub const SYNDROME_BYTES: usize = M / 8; // 2048 bytes
pub const SESSION_KEY_BYTES: usize = 32;

pub const AES_CTR_NONCE_BYTES: usize = 16;
pub const MAX_PAYLOAD_BYTES: usize = 8000;

pub const PADDING_DIGITS: usize = 5000;
pub const SUPERBLOCK_DIGITS: usize = 2 * M + PADDING_DIGITS; // 37768 digits

// Steganographic uniformity test threshold (chi-squared, df=9, p>0.05)
pub const CHI_SQUARED_THRESHOLD: f64 = 16.919;

// Keygen DFR validation trials (270 = statistical confidence for DFR < 2^-128)
pub const DFR_TRIALS: usize = 270;
