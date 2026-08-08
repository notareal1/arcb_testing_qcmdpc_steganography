// dfr_benchmark.rs -- ARCB v5.0
// DFR (Decoding Failure Rate) benchmark for t=134, M=16394
// Run with: cargo test --test dfr_benchmark -- --nocapture

use arcb_stegano_trapdoor::*;
use rand::Rng;
use std::time::Instant;

#[test]
fn test_dfr_benchmark() {
    let mut successes = 0;
    let mut failures = 0;
    let trials = 20; // Increase for production DFR estimation

    let start = Instant::now();

    for trial in 0..trials {
        let seed = [trial as u8; SEED_BYTES];
        let (h0p, h1p) = utils::derive_secret_polynomials(&seed).unwrap();
        let h0 = matrix::Circulant::new(h0p.clone());
        let h1 = matrix::Circulant::new(h1p.clone());

        // Generate random error of weight ERROR_WEIGHT
        let mut rng = rand::thread_rng();
        let mut bits = vec![0u8; 2 * M];
        let mut pos: Vec<usize> = (0..2 * M).collect();
        for i in 0..ERROR_WEIGHT {
            let j = rng.gen_range(i..2 * M);
            pos.swap(i, j);
            bits[pos[i]] = 1;
        }

        let e0 = polynomial::Polynomial::from_bits(&bits[..M]).unwrap();
        let e1 = polynomial::Polynomial::from_bits(&bits[M..]).unwrap();

        // Compute syndrome
        let s = h0.compute_syndrome(&e0).add(&h1.compute_syndrome(&e1));

        // Decode
        let (d0, d1, converged) = decoder::decode(&s, &h0, &h1);

        if converged && d0.equals(&e0) && d1.equals(&e1) {
            successes += 1;
        } else {
            failures += 1;
        }

        let elapsed = start.elapsed();
        eprintln!(
            "trial {trial}: {} successes, {} failures, elapsed: {:?}",
            successes, failures, elapsed
        );
    }

    let total = successes + failures;
    let dfr = failures as f64 / total as f64;
    eprintln!(
        "\nDFR benchmark: {}/{} successes, DFR ≈ {:.4}%, total time: {:?}",
        successes, total, dfr * 100.0,
        start.elapsed()
    );

    // For production, DFR should be < 10^-7
    // This demo test just verifies the decoder works
    assert!(successes > 0, "Decoder should succeed at least once");
}
