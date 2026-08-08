// lib.rs -- ARCB-SteganoTrapdoor v5.0 (Production)
// QC-MDPC Niederreiter KEM with Steganographic Encoding
// M=16384, w=45, t=134
//
// BGF decoder: ~196-bit classical / ~98-bit quantum (NIST Level 3-5)

pub mod decoder;
pub mod error;
pub mod kem;
pub mod keygen;
pub mod matrix;
pub mod parameters;
pub mod polynomial;
pub mod stego;
pub mod utils;

pub use error::{ArcError, ArcResult};
pub use kem::KemCiphertext;
pub use keygen::KeyPair;
pub use parameters::*;
pub use polynomial::Polynomial;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// High-level KEM encapsulate API.
pub fn encapsulate(
    public_key: &polynomial::Polynomial,
) -> (kem::KemCiphertext, [u8; SESSION_KEY_BYTES]) {
    kem::encapsulate(public_key)
}

/// High-level KEM decapsulate API.
pub fn decapsulate(
    seed: &[u8; parameters::SEED_BYTES],
    ciphertext: &kem::KemCiphertext,
) -> ArcResult<[u8; SESSION_KEY_BYTES]> {
    kem::decapsulate(seed, ciphertext)
}
