// examples/benchmark.rs — Decoder speed benchmark
use arcb_stegano_trapdoor::decoder::decode;
use arcb_stegano_trapdoor::keygen;
use arcb_stegano_trapdoor::matrix::Circulant;
use arcb_stegano_trapdoor::parameters::*;
use arcb_stegano_trapdoor::polynomial::Polynomial;
use arcb_stegano_trapdoor::utils;
use rand::Rng;
use std::time::Instant;

fn main() {
    println!("=== ARCB v5.2 Decoder Benchmark ===\n");

    // Generate key
    let seed = [0xABu8; SEED_BYTES];
    let (h0p, h1p) = utils::derive_secret_polynomials(&seed).unwrap();
    let h0 = Circulant::new(h0p.clone());
    let h1 = Circulant::new(h1p.clone());

    // Benchmark t=1 decode
    let mut rng = rand::thread_rng();
    let mut bits = vec![0u8; 2 * M];
    let j = rng.gen_range(0..2 * M);
    bits[j] = 1;
    let e0 = Polynomial::from_bits(&bits[..M]).unwrap();
    let e1 = Polynomial::from_bits(&bits[M..]).unwrap();
    let s = h0.compute_syndrome(&e0).add(&h1.compute_syndrome(&e1));

    let start = Instant::now();
    for _ in 0..10 {
        let (_d0, _d1, converged) = decode(&s, &h0, &h1);
        assert!(converged);
    }
    let t1_avg = start.elapsed() / 10;
    println!("  t=1 decode (avg of 10): {:?}", t1_avg);

    // Benchmark t=134 decode
    let mut bits = vec![0u8; 2 * M];
    let mut pos: Vec<usize> = (0..2 * M).collect();
    for i in 0..ERROR_WEIGHT {
        let j = rng.gen_range(i..2 * M);
        pos.swap(i, j);
        bits[pos[i]] = 1;
    }
    let e0 = Polynomial::from_bits(&bits[..M]).unwrap();
    let e1 = Polynomial::from_bits(&bits[M..]).unwrap();
    let s = h0.compute_syndrome(&e0).add(&h1.compute_syndrome(&e1));

    let start = Instant::now();
    for _ in 0..10 {
        let (_d0, _d1, converged) = decode(&s, &h0, &h1);
        assert!(converged, "t=134 decode failed!");
    }
    let t134_avg = start.elapsed() / 10;
    println!("  t={} decode (avg of 10): {:?}", ERROR_WEIGHT, t134_avg);

    // Benchmark KEM roundtrip
    let kp = keygen::from_seed(seed).unwrap();
    let (h0p, h1p) = utils::derive_secret_polynomials(&kp.seed).unwrap();
    let h0 = Circulant::new(h0p);
    let h1 = Circulant::new(h1p);

    let start = Instant::now();
    for _ in 0..5 {
        let (ct, k1) = arcb_stegano_trapdoor::kem::encapsulate(&kp.public);
        let k2 = arcb_stegano_trapdoor::kem::decapsulate_cached(&kp.seed, &h0, &h1, &ct).unwrap();
        assert_eq!(k1, k2);
    }
    let kem_avg = start.elapsed() / 5;
    println!("  KEM roundtrip (avg of 5, cached): {:?}", kem_avg);

    println!("\n=== Summary ===");
    println!("  Decoder speed: t=1 ~{:?}, t={} ~{:?}", t1_avg, ERROR_WEIGHT, t134_avg);
    println!("  KEM roundtrip: ~{}", format_duration(kem_avg));
}

fn format_duration(d: std::time::Duration) -> String {
    if d.as_secs() > 0 {
        format!("{:.2}s", d.as_secs_f64())
    } else {
        format!("{}ms", d.as_millis())
    }
}
