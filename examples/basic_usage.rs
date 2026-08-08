// basic_usage.rs -- ARCB v3.0

use arcb_stegano_trapdoor::*;

fn main() {
    println!("============================================");
    println!("  ARCB v{} — QC-MDPC Niederreiter KEM", VERSION);
    println!("============================================\n");

    // 1. Key generation.
    println!("[*] Generating key pair...");
    let kp = keygen::generate().expect("keygen failed");
    println!("    Public key : {} bytes", kp.public.as_bytes().len());
    println!("    Secret seed: {} bytes\n", kp.seed.len());

    // 2. Encapsulation.
    println!("[*] Encapsulating...");
    let t = std::time::Instant::now();
    let (ct, session_key) = kem::encapsulate(&kp.public);
    let enc_time = t.elapsed();
    println!("    Syndrome   : {} bytes", ct.syndrome.len());
    println!("    Session key: {:02x?}...", &session_key[..8]);
    println!("    Time       : {:?}\n", enc_time);

    // 3. Decapsulation (one-shot).
    println!("[*] Decapsulating (one-shot)...");
    let t = std::time::Instant::now();
    let k2 = kem::decapsulate(&kp.seed, &ct).expect("decaps failed");
    let dec_time = t.elapsed();
    println!("    Session key: {:02x?}...", &k2[..8]);
    println!("    Time       : {:?}\n", dec_time);

    assert_eq!(session_key, k2);
    println!("[OK] Roundtrip SUCCESS.\n");

    // 4. Fast path.
    println!("[*] Cached secret key...");
    let (h0p, h1p) = utils::derive_secret_polynomials(&kp.seed).unwrap();
    let h0 = matrix::Circulant::new(h0p);
    let h1 = matrix::Circulant::new(h1p);

    let t = std::time::Instant::now();
    let (_ct, k1) = kem::encapsulate(&kp.public);
    let k2 = kem::decapsulate_cached(&kp.seed, &h0, &h1, &_ct).unwrap();
    let cached_time = t.elapsed();
    assert_eq!(k1, k2);
    println!("    Cached time: {:?}\n", cached_time);

    println!("============================================");
    println!("  Ciphertext: {} bytes", ct.syndrome.len());
    println!("  Encaps    : {:?}", enc_time);
    println!("  Decaps    : {:?} (one-shot)", dec_time);
    println!("  Decaps    : {:?} (cached)", cached_time);
    println!("============================================");
}
