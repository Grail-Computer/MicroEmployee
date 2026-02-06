use anyhow::Context;

use aes_gcm::aead::Aead;
use aes_gcm::aead::KeyInit;
use aes_gcm::Aes256Gcm;
use aes_gcm::Nonce;
use rand::rngs::OsRng;
use rand::TryRngCore;

pub struct Crypto {
    cipher: Aes256Gcm,
}

impl Crypto {
    pub fn new(master_key: &[u8; 32]) -> Self {
        let cipher = Aes256Gcm::new_from_slice(master_key).expect("32 bytes");
        Self { cipher }
    }

    pub fn encrypt(&self, aad: &[u8], plaintext: &[u8]) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
        let mut nonce_bytes = [0u8; 12];
        let mut rng = OsRng;
        rng.try_fill_bytes(&mut nonce_bytes)
            .map_err(|_| anyhow::anyhow!("os rng failure"))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, aes_gcm::aead::Payload { msg: plaintext, aad })
            .map_err(|_| anyhow::anyhow!("encrypt failed"))?;

        Ok((nonce_bytes.to_vec(), ciphertext))
    }

    pub fn decrypt(&self, aad: &[u8], nonce: &[u8], ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(nonce.len() == 12, "invalid nonce length");
        let nonce = Nonce::from_slice(nonce);
        let plaintext = self
            .cipher
            .decrypt(nonce, aes_gcm::aead::Payload { msg: ciphertext, aad })
            .map_err(|_| anyhow::anyhow!("decrypt failed"))?;
        Ok(plaintext)
    }
}

pub fn parse_master_key(value: &str) -> anyhow::Result<[u8; 32]> {
    use base64::Engine;

    let s = value.trim();
    anyhow::ensure!(!s.is_empty(), "master key is empty");

    // Prefer hex when it matches exactly 32 bytes.
    if let Ok(bytes) = hex::decode(s) {
        if bytes.len() == 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            return Ok(out);
        }
    }

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s)
        .context("decode master key as base64")?;
    anyhow::ensure!(bytes.len() == 32, "master key must be 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
