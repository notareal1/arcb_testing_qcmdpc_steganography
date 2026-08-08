// fuzz_decoder.rs -- AFL++ fuzzing harness for ARCB v4.0 decoder.
//
// Fuzz target: feed arbitrary data as syndrome to the decoder pipeline
// and check for infinite loops, crashes, or unexpected behavior.
//
// Run with:
//   cargo afl build --release -p arcb-fuzz --bin fuzz_decoder
//   cargo afl fuzz -i fuzz/corpus -o fuzz/output target/release/fuzz_decoder

use arcb_stegano_trapdoor::parameters::*;
use arcb_stegano_trapdoor::polynomial::Polynomial;
use arcb_stegano_trapdoor::matrix::Circulant;
use arcb_stegano_trapdoor::decoder::decode;
use arcb_stegano_trapdoor::utils;

fn main() {
    afl::fuzz!(|data: &[u8]| {
        // Need SYNDROME_BYTES + SEED_BYTES to derive both syndrome and key.
        let needed = SYNDROME_BYTES + SEED_BYTES;
        if data.len() < needed {
            return;
        }

        // Derive syndrome from first SYNDROME_BYTES of input.
        let mut syndrome_bytes = [0u8; SYNDROME_BYTES];
        syndrome_bytes.copy_from_slice(&data[..SYNDROME_BYTES]);
        let syndrome = Polynomial::from_bytes(&syndrome_bytes);

        // Derive seed from remaining bytes — allows fuzzer to explore
        // many different key/syndrome combinations.
        let mut seed = [0u8; SEED_BYTES];
        seed.copy_from_slice(&data[SYNDROME_BYTES..needed]);

        if let Ok((h0_poly, h1_poly)) = utils::derive_secret_polynomials(&seed) {
            let h0 = Circulant::new(h0_poly);
            let h1 = Circulant::new(h1_poly);

            // Attempt to decode. The decoder has MAX_ITER bound,
            // so it should always terminate.
            let _result = decode(&syndrome, &h0, &h1);
        }
    });
}
