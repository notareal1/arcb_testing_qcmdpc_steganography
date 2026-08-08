
#[test]
fn test_public_key_looks_random() {
    use arcb_stegano_trapdoor::*;
    
    let kp = keygen::generate().unwrap();
    let pk = kp.public.as_bytes();
    
    // Check bit density - should be close to 0.5 for random
    let ones = pk.iter().map(|&b| b.count_ones() as usize).sum::<usize>();
    let total_bits = pk.len() * 8;
    let ratio = ones as f64 / total_bits as f64;
    
    println!("Public key bit density: {}/{} = {:.4}", ones, total_bits, ratio);
    assert!(ratio > 0.4 && ratio < 0.6, "PK bit density {:.4} not close to 0.5", ratio);
    
    // Check syndrome also looks random
    let (ct, _) = kem::encapsulate(&kp.public);
    let syndrome = &ct.syndrome;
    let syn_ones = syndrome.iter().map(|&b| b.count_ones() as usize).sum::<usize>();
    let syn_total = syndrome.len() * 8;
    let syn_ratio = syn_ones as f64 / syn_total as f64;
    
    println!("Syndrome bit density: {}/{} = {:.4}", syn_ones, syn_total, syn_ratio);
    assert!(syn_ratio > 0.4 && syn_ratio < 0.6, "Syndrome bit density {:.4} not close to 0.5", syn_ratio);
    
    // Print first bytes to verify
    println!("PK first 32 bytes: {:?}", &pk[..32]);
    println!("Syndrome first 32 bytes: {:?}", &syndrome[..32]);
}
