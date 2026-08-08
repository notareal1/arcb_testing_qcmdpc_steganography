// benchmark_heavy.rs — ARCB v5.0 Heavy Load Test (Parallel)
// 3000 messages x 200 bytes each, full E2EE pipeline with rayon parallelism

use arcb_stegano_trapdoor::*;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use blake3;
use rayon::prelude::*;
use std::time::Instant;

fn kdf(session_key: &[u8; 32], counter: u64) -> ([u8; 32], [u8; 12]) {
    let mut inp = Vec::with_capacity(32 + 8);
    inp.extend_from_slice(session_key);
    inp.extend_from_slice(&counter.to_le_bytes());
    let h = blake3::hash(&inp);
    let full: [u8; 32] = h.into();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&full[..12]);
    (full, nonce)
}

fn encrypt(session_key: &[u8; 32], counter: u64, plaintext: &[u8]) -> Vec<u8> {
    let (enc_key, nonce_bytes) = kdf(session_key, counter);
    let cipher = Aes256Gcm::new((&enc_key).into());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut ct = plaintext.to_vec();
    cipher.encrypt_in_place(nonce, b"", &mut ct).unwrap();
    let mut pkt = Vec::with_capacity(8 + 12 + ct.len());
    pkt.extend_from_slice(&counter.to_le_bytes());
    pkt.extend_from_slice(&nonce_bytes);
    pkt.extend_from_slice(&ct);
    pkt
}

fn decrypt(session_key: &[u8; 32], packet: &[u8]) -> Result<Vec<u8>, String> {
    let counter = u64::from_le_bytes(packet[..8].try_into().map_err(|e| format!("{e}"))?);
    let (enc_key, nonce_bytes) = kdf(session_key, counter);
    let cipher = Aes256Gcm::new((&enc_key).into());
    let nonce = Nonce::from_slice(&nonce_bytes);
    let mut pt = packet[20..].to_vec();
    cipher.decrypt_in_place(nonce, b"", &mut pt).map_err(|_| "auth failed".to_string())?;
    Ok(pt)
}

fn main() {
    let msg_count: usize = 3000;
    let msg_len: usize = 200;

    println!("╔══════════════════════════════════════════════════════╗");
    println!("║  ARCB v5.0 — Heavy E2EE Benchmark (Parallel)       ║");
    println!("║  {msg_count} messages x {msg_len} bytes each                     ║");
    println!("╚══════════════════════════════════════════════════════╝");
    println!();

    // ── Setup ──
    println!("━━━ Phase 1: Key Generation ━━━");
    let t = Instant::now();
    let bob_kp = keygen::generate().expect("keygen failed");
    let (h0p, h1p) = utils::derive_secret_polynomials(&bob_kp.seed).unwrap();
    let h0 = matrix::Circulant::new(h0p);
    let h1 = matrix::Circulant::new(h1p);
    println!("  Bob keygen in {:?}", t.elapsed());
    println!();

    // ── Generate messages ──
    println!("━━━ Phase 2: Generating {msg_count} messages ━━━");
    let messages: Vec<Vec<u8>> = (0..msg_count)
        .map(|i| {
            let text = format!(
                "Tin nhan so {i} — Day la bai van do dai de kiem thu ARCB KEM E2EE. \
                 QC-MDPC Niederreiter ma hoa bao mat luong tu. \
                 Moi tin nhan dung encapsulation moi cho forward secrecy hoan toan. \
                 Day la phan noi dung chinh cua tin nhan nay. \
                 Ket thuc tin nhan.{}",
                "x".repeat(msg_len.saturating_sub(200))
            );
            let bytes = text.into_bytes();
            if bytes.len() >= msg_len { bytes[..msg_len].to_vec() } else { let mut p = bytes; p.resize(msg_len, b' '); p }
        })
        .collect();
    let total_plain: usize = messages.iter().map(|m| m.len()).sum();
    println!("  Total plaintext: {} bytes ({} KB)", total_plain, total_plain / 1024);
    println!();

    // ── Encapsulate + Encrypt (sequential) ──
    println!("━━━ Phase 3: Encapsulate + Encrypt ━━━");
    let t = Instant::now();
    let mut kem_cts = Vec::with_capacity(msg_count);
    let mut packets = Vec::with_capacity(msg_count);
    for (i, msg) in messages.iter().enumerate() {
        let (ct, sk) = kem::encapsulate(&bob_kp.public);
        let pkt = encrypt(&sk, i as u64, msg);
        kem_cts.push(ct);
        packets.push(pkt);
    }
    let enc_time = t.elapsed();
    let total_kem: usize = kem_cts.iter().map(|c| c.syndrome.len()).sum();
    let total_pkt: usize = packets.iter().map(|p| p.len()).sum();
    println!("  Encrypted {msg_count} msgs in {enc_time:?}");
    println!("  KEM CTs: {} MB | Packets: {} KB", total_kem / 1024 / 1024, total_pkt / 1024);
    println!("  Avg: {:?}/msg | Throughput: {:.1} msg/s", enc_time / msg_count as u32, msg_count as f64 / enc_time.as_secs_f64());
    println!();

    // ── Decapsulate + Decrypt (PARALLEL with rayon) ──
    println!("━━━ Phase 4: Decapsulate + Decrypt (parallel, {} threads) ━━━", rayon::current_num_threads());
    let t = Instant::now();
    let decrypted: Vec<Vec<u8>> = (0..msg_count)
        .into_par_iter()
        .map(|i| {
            let sk = kem::decapsulate_cached(&bob_kp.seed, &h0, &h1, &kem_cts[i]).expect("decaps failed");
            decrypt(&sk, &packets[i]).expect("decrypt failed")
        })
        .collect();
    let dec_time = t.elapsed();
    println!("  Decrypted {msg_count} msgs in {dec_time:?}");
    println!("  Avg: {:?}/msg | Throughput: {:.1} msg/s", dec_time / msg_count as u32, msg_count as f64 / dec_time.as_secs_f64());
    println!();

    // ── Verify ──
    println!("━━━ Phase 5: Verification ━━━");
    let mut ok = 0usize;
    let mut fail = 0usize;
    for i in 0..msg_count {
        if decrypted[i] == messages[i] { ok += 1; } else {
            fail += 1;
            if fail <= 3 {
                let preview_orig = String::from_utf8_lossy(&messages[i][..80.min(messages[i].len())]);
                let preview_dec = String::from_utf8_lossy(&decrypted[i][..80.min(decrypted[i].len())]);
                println!("  FAIL msg #{}: orig='{}...' dec='{}...'", i, preview_orig, preview_dec);
            }
        }
    }
    println!("  OK: {ok}/{msg_count}  FAIL: {fail}");
    println!();

    // ── Tamper test ──
    println!("━━━ Phase 6: Tamper Resistance (10 samples) ━━━");
    let mut tamper_ok = 0usize;
    let tamper_n = 10.min(msg_count);
    for i in 0..tamper_n {
        let mut bad = packets[i].clone();
        let idx = 20 + (bad.len() - 20) / 2;
        if idx < bad.len() { bad[idx] ^= 0xFF; }
        let sk = kem::decapsulate_cached(&bob_kp.seed, &h0, &h1, &kem_cts[i]);
        if let Ok(sk) = sk {
            if decrypt(&sk, &bad).is_err() { tamper_ok += 1; }
        }
    }
    println!("  Tamper rejected: {tamper_ok}/{tamper_n}");
    println!();

    // ── Summary ──
    let total_time = enc_time + dec_time;
    let total_mb = (total_plain + total_kem + total_pkt) as f64 / 1_048_576.0;
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║  SUMMARY                                           ║");
    println!("╠══════════════════════════════════════════════════════╣");
    println!("║  Messages     : {msg_count:>6}                       ║");
    println!("║  Msg size     : {msg_len:>6} bytes                  ║");
    println!("║  Plaintext    : {:>6} KB                          ║", total_plain / 1024);
    println!("║  KEM CTs      : {:>6} MB                          ║", total_kem / 1024 / 1024);
    println!("║  Packets      : {:>6} KB                          ║", total_pkt / 1024);
    println!("║  Total data   : {:>6.1} MB                        ║", total_mb);
    println!("╠══════════════════════════════════════════════════════╣");
    println!("║  Enc time     : {:>12?}                       ║", enc_time);
    println!("║  Dec time     : {:>12?}                       ║", dec_time);
    println!("║  Total time   : {:>12?}                       ║", total_time);
    println!("║  Enc speed    : {:>6.1} msg/s                    ║", msg_count as f64 / enc_time.as_secs_f64());
    println!("║  Dec speed    : {:>6.1} msg/s                    ║", msg_count as f64 / dec_time.as_secs_f64());
    println!("║  Verified     : {:>6}/{} OK                       ║", ok, msg_count);
    println!("║  Tamper reject: {:>6}/{} OK                       ║", tamper_ok, tamper_n);
    println!("╚══════════════════════════════════════════════════════╝");
}
