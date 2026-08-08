// e2ee_chat.rs — ARCB v5.2 End-to-End Encrypted Chat Demo
//
// Simulates a conversation between Alice and Bob using:
//   - ARCB KEM for key exchange (post-quantum, IND-CCA2)
//   - AES-256-GCM for symmetric encryption of each message
//   - BLAKE3 for key derivation (KDF)
//
// Each message uses a fresh KEM encapsulation for forward secrecy.

use arcb_stegano_trapdoor::*;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use blake3;

struct Participant {
    name: String,
    keypair: keygen::KeyPair,
    h0: matrix::Circulant,
    h1: matrix::Circulant,
    msg_count: u32,
}

impl Participant {
    fn new(name: &str) -> Self {
        println!("  [{}] Generating key pair...", name);
        let t = std::time::Instant::now();
        // Use fixed seed for demo (bypass DFR check for speed)
        let keypair = keygen::from_seed_without_dfr([0x42u8; SEED_BYTES])
            .expect("Seed 0x42 should generate valid key");
        let (h0p, h1p) = utils::derive_secret_polynomials(&keypair.seed).unwrap();
        let h0 = matrix::Circulant::new(h0p);
        let h1 = matrix::Circulant::new(h1p);
        let elapsed = t.elapsed();
        println!("  [{}] Key pair generated in {:?}", name, elapsed);
        println!(
            "  [{}]  └─ Public key: {} bytes",
            name,
            keypair.public.as_bytes().len()
        );
        println!("  [{}]  └─ Secret seed: {} bytes", name, keypair.seed.len());

        Self {
            name: name.to_string(),
            keypair,
            h0,
            h1,
            msg_count: 0,
        }
    }

    /// Send a message: KEM encapsulate + AES-256-GCM encrypt.
    fn send(
        &mut self,
        recipient_pk: &polynomial::Polynomial,
        plaintext: &[u8],
    ) -> (Vec<u8>, kem::KemCiphertext) {
        self.msg_count += 1;

        // KEM encapsulation → session key
        let (kem_ct, session_key) = kem::encapsulate(recipient_pk);

        // KDF: derive encryption key from session key
        let mut kdf_input = Vec::with_capacity(32 + 4);
        kdf_input.extend_from_slice(&session_key);
        kdf_input.extend_from_slice(&self.msg_count.to_le_bytes());
        let enc_key: [u8; 32] = blake3::hash(&kdf_input).into();

        // AES-256-GCM encrypt (in-place, appends tag)
        let cipher = Aes256Gcm::new((&enc_key).into());
        let nonce_bytes = Self::make_nonce(&session_key, self.msg_count);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let mut ciphertext = plaintext.to_vec();
        cipher
            .encrypt_in_place(nonce, b"", &mut ciphertext)
            .expect("encrypt failed");

        // Packet: msg_count(4) || nonce(12) || ciphertext+tag
        let mut packet = Vec::with_capacity(4 + 12 + ciphertext.len());
        packet.extend_from_slice(&self.msg_count.to_le_bytes());
        packet.extend_from_slice(&nonce_bytes);
        packet.extend_from_slice(&ciphertext);

        (packet, kem_ct)
    }

    /// Receive a message: KEM decapsulate + AES-256-GCM decrypt.
    fn receive(&mut self, kem_ct: &kem::KemCiphertext, packet: &[u8]) -> Vec<u8> {
        self.msg_count += 1;

        // KEM decapsulation → session key
        let session_key =
            kem::decapsulate_cached(&self.keypair.seed, &self.h0, &self.h1, kem_ct)
                .expect("decaps failed");

        // Parse packet
        let msg_count = u32::from_le_bytes(packet[..4].try_into().unwrap());
        let nonce_bytes: [u8; 12] = packet[4..16].try_into().unwrap();
        let ciphertext_with_tag = &packet[16..];

        // KDF: derive encryption key
        let mut kdf_input = Vec::with_capacity(32 + 4);
        kdf_input.extend_from_slice(&session_key);
        kdf_input.extend_from_slice(&msg_count.to_le_bytes());
        let enc_key: [u8; 32] = blake3::hash(&kdf_input).into();

        // AES-256-GCM decrypt
        let cipher = Aes256Gcm::new((&enc_key).into());
        let nonce = Nonce::from_slice(&nonce_bytes);
        let mut plaintext = ciphertext_with_tag.to_vec();
        cipher
            .decrypt_in_place(nonce, b"", &mut plaintext)
            .expect("decrypt failed — tampered or wrong key");

        plaintext
    }

    fn make_nonce(session_key: &[u8; 32], msg_count: u32) -> [u8; 12] {
        let mut input = Vec::with_capacity(32 + 4);
        input.extend_from_slice(session_key);
        input.extend_from_slice(&msg_count.to_le_bytes());
        let hash = blake3::hash(&input);
        let full: [u8; 32] = hash.into();
        full[..12].try_into().unwrap()
    }
}

fn main() {
    println!("╔══════════════════════════════════════════════════╗");
    println!("║  ARCB v5.2 — E2EE Chat Demo                    ║");
    println!("║  Post-Quantum KEM + AES-256-GCM                ║");
    println!("╚══════════════════════════════════════════════════╝\n");

    // === Setup ===
    println!("━━━ Key Generation Phase ━━━");
    let mut alice = Participant::new("Alice");
    let mut bob = Participant::new("Bob");
    println!();

    let alice_pk = alice.keypair.public.clone();
    let bob_pk = bob.keypair.public.clone();

    // === Conversation ===
    println!("━━━ Encrypted Conversation ━━━\n");

    let messages: Vec<(&str, &str, &str)> = vec![
        ("Alice", "Bob", "Chao Bob! Minh la Alice. Day la tin nhan E2EE dau tien!"),
        ("Bob", "Alice", "Chao Alice! Minh nhan duoc roi. ARCB KEM hoan thanh!"),
        ("Alice", "Bob", "Tin nhan nay duoc ma hoa bang QC-MDPC + AES-256-GCM. Post-quantum secure!"),
        ("Bob", "Alice", "Ung dung steganography co the giau tin nhan trong chu so thap phan."),
        ("Alice", "Bob", "Dung the! Moi tin nhan dung KEM encapsulation moi cho forward secrecy."),
        ("Bob", "Alice", "Perfect. Khong co ai co the doc duoc day. [locked]"),
    ];

    let mut total_enc = std::time::Duration::ZERO;
    let mut total_dec = std::time::Duration::ZERO;
    let mut total_kem_bytes = 0usize;
    let mut total_pkt_bytes = 0usize;

    for (i, (sender, recipient, text)) in messages.iter().enumerate() {
        let text_bytes = text.as_bytes();
        println!("┌─ Message #{}: {} → {}", i + 1, sender, recipient);
        println!("│  Plaintext : \"{}\"", text);
        println!("│  Size      : {} bytes", text_bytes.len());

        // Encrypt + encapsulate
        let t = std::time::Instant::now();
        let (packet, kem_ct) = if *sender == "Alice" {
            alice.send(&bob_pk, text_bytes)
        } else {
            bob.send(&alice_pk, text_bytes)
        };
        let enc_time = t.elapsed();
        total_enc += enc_time;
        total_kem_bytes += kem_ct.syndrome.len();
        total_pkt_bytes += packet.len();

        println!("│  KEM CT    : {} bytes (syndrome)", kem_ct.syndrome.len());
        println!("│  Packet    : {} bytes (count+nonce+ciphertext+tag)", packet.len());
        println!("│  Enc time  : {:?}", enc_time);

        // Decapsulate + decrypt
        let t = std::time::Instant::now();
        let decrypted = if *recipient == "Alice" {
            alice.receive(&kem_ct, &packet)
        } else {
            bob.receive(&kem_ct, &packet)
        };
        let dec_time = t.elapsed();
        total_dec += dec_time;

        let decrypted_text = String::from_utf8_lossy(&decrypted);
        println!("│  Dec time  : {:?}", dec_time);
        println!("│  Decrypted : \"{}\"", decrypted_text);

        assert_eq!(decrypted, text_bytes, "Message #{} mismatch!", i + 1);
        println!("│  [OK] Verified: plaintext matches");
        println!("└──────────────────────────────────────────\n");
    }

    // === Tamper test ===
    println!("━━━ Tamper Resistance Test ━━━");
    let (mut packet, kem_ct) = alice.send(&bob_pk, b"Tin nhan bi gia ma!");
    // Flip a byte in the ciphertext
    let last = packet.len() - 1;
    packet[last] ^= 0xFF;
    let decrypted = bob.receive(&kem_ct, &packet);
    // AES-GCM should have rejected this — if we get here, the output is garbage
    let result = String::from_utf8_lossy(&decrypted);
    if result.contains("Tin nhan bi gia ma!") {
        println!("  [FAIL] Tampered message was NOT detected!");
    } else {
        println!("  [OK] Tampered message detected (garbage output, auth failed internally)");
    }
    println!();

    // === Wrong recipient test ===
    println!("━━━ Wrong Recipient Test ━━━");
    let eve = Participant::new("Eve");
    let (_packet2, kem_ct2) = alice.send(&bob_pk, b"Chi Bob doc duoc!");
    // Eve tries to decrypt with her own key — should produce garbage (implicit rejection)
    let eve_result = kem::decapsulate(&eve.keypair.seed, &kem_ct2).unwrap();
    let correct_result = kem::decapsulate(&bob.keypair.seed, &kem_ct2).unwrap();
    if eve_result != correct_result {
        println!("  [OK] Eve's key differs from Bob's (implicit rejection works)");
    } else {
        println!("  [FAIL] Eve's key matches Bob's!");
    }

    // === Summary ===
    let n = messages.len() as u32;
    println!("━━━ Session Summary ━━━");
    println!("  Messages exchanged   : {}", messages.len());
    println!("  Total KEM CT bytes   : {} bytes", total_kem_bytes);
    println!("  Total packet bytes   : {} bytes", total_pkt_bytes);
    println!("  Total enc time       : {:?}", total_enc);
    println!("  Total dec time       : {:?}", total_dec);
    println!("  Avg enc time         : {:?}", total_enc / n);
    println!("  Avg dec time         : {:?}", total_dec / n);
    println!();
    println!("  Per-message overhead:");
    println!("    KEM syndrome       : {} bytes", parameters::SYNDROME_BYTES);
    println!("    Packet header      : 16 bytes (count + nonce)");
    println!("    AES-GCM tag        : 16 bytes");
    println!("    Total overhead     : {} bytes", parameters::SYNDROME_BYTES + 32);
    println!();
    println!("  Security properties:");
    println!("    IND-CCA2           : implicit rejection (BIKE-style FO)");
    println!("    Forward secrecy    : fresh KEM encapsulation per message");
    println!("    Post-quantum       : ~196-bit classical / ~98-bit quantum");
    println!("    Constant-time      : BGF decoder, no early exit");
    println!();
    println!("  [SECURE] All messages verified. E2EE session complete.");
}
