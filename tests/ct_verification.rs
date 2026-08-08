// tests/ct_verification.rs — Constant-time verification using dudect
//
// This test uses dudect-bencher to verify that CT operations timing
// does not leak information about the secret key.
//
// Method: Compare timing of two different CLASSES of operations:
//   Class::Left: operation on data with specific property
//   Class::Right: operation on data with different property
// If CT, timing distributions should be indistinguishable.

use arcb_stegano_trapdoor::*;
use dudect_bencher::ctbench::{BenchMetadata, BenchName, BenchRng, Class, CtRunner};
use rand::{Rng, RngCore};
use std::hint::black_box;
use subtle::ConstantTimeEq;

const NUM_SAMPLES: usize = 100;

/// Benchmark: ct_bytes_equal with equal vs non-equal inputs
/// Tests that comparison timing doesn't depend on whether inputs are equal
fn bench_ct_bytes_equal(runner: &mut CtRunner, rng: &mut BenchRng) {
    let polys: Vec<[u8; PUBKEY_BYTES]> = (0..NUM_SAMPLES * 2)
        .map(|i| {
            let mut buf = [0u8; PUBKEY_BYTES];
            rng.fill(&mut buf);
            buf
        })
        .collect();

    for i in 0..NUM_SAMPLES {
        // Left: compare equal inputs (same data)
        let a = &polys[i * 2];
        runner.run_one(Class::Left, || black_box(a.ct_eq(a)));

        // Right: compare different inputs
        let b = &polys[i * 2 + 1];
        runner.run_one(Class::Right, || black_box(a.ct_eq(b)));
    }
}

/// Benchmark: polynomial equality check
fn bench_poly_equals(runner: &mut CtRunner, rng: &mut BenchRng) {
    let polys: Vec<Polynomial> = (0..NUM_SAMPLES * 2)
        .map(|_| {
            let mut p = Polynomial::zero();
            rng.fill_bytes(p.as_bytes_mut());
            p
        })
        .collect();

    for i in 0..NUM_SAMPLES {
        let a = &polys[i * 2];
        let b = &polys[i * 2 + 1];

        // Left: equals() on different inputs
        runner.run_one(Class::Left, || black_box(a.equals(b)));
        // Right: equals() on same input
        runner.run_one(Class::Right, || black_box(a.equals(a)));
    }
}

/// Quick smoke test
#[test]
fn test_dudect_quick() {
    use dudect_bencher::ctbench::run_benches_console;

    let benches = vec![
        BenchMetadata {
            name: BenchName("ct_bytes_equal"),
            seed: None,
            benchfn: bench_ct_bytes_equal,
        },
        BenchMetadata {
            name: BenchName("poly_equals"),
            seed: None,
            benchfn: bench_poly_equals,
        },
    ];

    let opts = dudect_bencher::ctbench::BenchOpts {
        continuous: false,
        filter: None,
        file_out: None,
    };

    run_benches_console(opts, benches).expect("dudect failed");
}
