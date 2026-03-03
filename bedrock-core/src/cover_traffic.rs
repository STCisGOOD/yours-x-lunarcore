//! Constant-rate dummy traffic generation for timing analysis resistance.
//!
//! Fixed-size packets, timing jitter, and chaff traffic make real
//! messages indistinguishable from cover traffic.

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

/// Standard packet size for all traffic (real and cover).
/// Must match MeshCore MAX_PACKET_PAYLOAD.
pub const PACKET_SIZE: usize = 184;

/// Overhead: 12-byte nonce + 16-byte tag + 1-byte type marker
pub const OVERHEAD: usize = 12 + 16 + 1;

/// Maximum payload per packet
pub const MAX_PAYLOAD: usize = PACKET_SIZE - OVERHEAD;

/// Packet type markers (encrypted, so adversary can't distinguish)
const TYPE_REAL: u8 = 0x01;
const TYPE_CHAFF: u8 = 0x02;
const TYPE_HEARTBEAT: u8 = 0x03;
const TYPE_ACK: u8 = 0x04;

/// Cover traffic configuration
#[derive(Clone, Debug)]
pub struct CoverTrafficConfig {
    /// Base interval between packets in milliseconds
    pub base_interval_ms: u64,

    /// Maximum random jitter in milliseconds (added to base interval)
    pub jitter_ms: u64,

    /// Probability of sending chaff when no real traffic (0.0 - 1.0)
    pub chaff_probability: f64,

    /// Minimum chaff packets per minute (ensures constant traffic)
    pub min_chaff_per_minute: u32,

    /// Whether to pad all messages to fixed size
    pub enable_padding: bool,
}

impl Default for CoverTrafficConfig {
    fn default() -> Self {
        Self {
            base_interval_ms: 5000,     // 5 seconds base
            jitter_ms: 3000,            // +/- 3 seconds jitter
            chaff_probability: 0.3,     // 30% chance of chaff
            min_chaff_per_minute: 4,    // At least 4 chaff per minute
            enable_padding: true,
        }
    }
}

/// Cover traffic generator
pub struct CoverTrafficGenerator {
    config: CoverTrafficConfig,
    rng: ChaCha20Rng,
    chaff_key: [u8; 32],  // Key for encrypting chaff (can be public - content is random)
    last_send_time: u64,
    chaff_count_this_minute: u32,
    minute_start: u64,
}

impl CoverTrafficGenerator {
    /// Create new generator with random seed
    pub fn new(config: CoverTrafficConfig) -> Self {
        let mut seed_rng = rand::thread_rng();
        let mut seed = [0u8; 32];
        seed_rng.fill(&mut seed);

        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut chaff_key = [0u8; 32];
        rng.fill(&mut chaff_key);

        Self {
            config,
            rng,
            chaff_key,
            last_send_time: 0,
            chaff_count_this_minute: 0,
            minute_start: 0,
        }
    }

    /// Create from deterministic seed (for testing)
    pub fn from_seed(seed: [u8; 32], config: CoverTrafficConfig) -> Self {
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut chaff_key = [0u8; 32];
        rng.fill(&mut chaff_key);

        Self {
            config,
            rng,
            chaff_key,
            last_send_time: 0,
            chaff_count_this_minute: 0,
            minute_start: 0,
        }
    }

    /// Pad a real message to fixed packet size.
    /// Format: [type(1)] [length(2)] [payload(variable)] [random padding] [nonce(12)] [tag(16)]
    pub fn pad_message(&mut self, key: &[u8; 32], plaintext: &[u8]) -> Result<[u8; PACKET_SIZE], &'static str> {
        if plaintext.len() > MAX_PAYLOAD - 2 {  // -2 for length field
            return Err("Payload too large for single packet");
        }

        let mut padded = [0u8; PACKET_SIZE];

        // Build plaintext: type + length + payload + random padding
        let mut inner = vec![TYPE_REAL];
        inner.extend_from_slice(&(plaintext.len() as u16).to_le_bytes());
        inner.extend_from_slice(plaintext);

        // Fill rest with random padding
        let padding_len = MAX_PAYLOAD - 2 - plaintext.len();
        let mut padding = vec![0u8; padding_len];
        self.rng.fill(&mut padding[..]);
        inner.extend_from_slice(&padding);

        // Encrypt with random nonce
        let mut nonce_bytes = [0u8; 12];
        self.rng.fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| "Invalid key")?;

        let ciphertext = cipher.encrypt(nonce, inner.as_slice())
            .map_err(|_| "Encryption failed")?;

        // Assemble packet: ciphertext (with tag) + nonce
        padded[..ciphertext.len()].copy_from_slice(&ciphertext);
        padded[ciphertext.len()..ciphertext.len() + 12].copy_from_slice(&nonce_bytes);

        Ok(padded)
    }

    /// Generate a chaff packet (random encrypted garbage).
    /// Indistinguishable from real traffic without the key.
    pub fn generate_chaff(&mut self) -> [u8; PACKET_SIZE] {
        let mut packet = [0u8; PACKET_SIZE];

        // Generate random "payload"
        let mut inner = vec![TYPE_CHAFF];
        let mut payload = vec![0u8; MAX_PAYLOAD];
        self.rng.fill(&mut payload[..]);
        inner.extend_from_slice(&payload);

        // Encrypt with chaff key
        let mut nonce_bytes = [0u8; 12];
        self.rng.fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = ChaCha20Poly1305::new_from_slice(&self.chaff_key).unwrap();
        let ciphertext = cipher.encrypt(nonce, inner.as_slice()).unwrap();

        packet[..ciphertext.len()].copy_from_slice(&ciphertext);
        packet[ciphertext.len()..ciphertext.len() + 12].copy_from_slice(&nonce_bytes);

        self.chaff_count_this_minute += 1;

        packet
    }

    /// Generate a heartbeat packet (proves liveness without content)
    pub fn generate_heartbeat(&mut self, key: &[u8; 32]) -> Result<[u8; PACKET_SIZE], &'static str> {
        let mut packet = [0u8; PACKET_SIZE];

        // Heartbeat is just type marker + random padding
        let mut inner = vec![TYPE_HEARTBEAT];
        let mut padding = vec![0u8; MAX_PAYLOAD];
        self.rng.fill(&mut padding[..]);
        inner.extend_from_slice(&padding);

        // Encrypt
        let mut nonce_bytes = [0u8; 12];
        self.rng.fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|_| "Invalid key")?;

        let ciphertext = cipher.encrypt(nonce, inner.as_slice())
            .map_err(|_| "Encryption failed")?;

        packet[..ciphertext.len()].copy_from_slice(&ciphertext);
        packet[ciphertext.len()..ciphertext.len() + 12].copy_from_slice(&nonce_bytes);

        Ok(packet)
    }

    /// Decrypt and unpad a received packet.
    /// Returns (packet_type, payload) or None if decryption fails.
    pub fn unpad_message(&self, key: &[u8; 32], packet: &[u8; PACKET_SIZE]) -> Option<(PacketType, Vec<u8>)> {
        // Extract nonce and ciphertext
        let nonce_start = PACKET_SIZE - OVERHEAD + 1;  // After type in encrypted form
        // Actually, nonce is at the end after tag
        // Ciphertext = PACKET_SIZE - 12 (nonce)
        // But ciphertext includes 16-byte tag

        let ciphertext_len = PACKET_SIZE - 12;
        let nonce_bytes = &packet[ciphertext_len..];
        let ciphertext = &packet[..ciphertext_len];

        let nonce = Nonce::from_slice(nonce_bytes);

        let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
        let plaintext = cipher.decrypt(nonce, ciphertext).ok()?;

        if plaintext.is_empty() {
            return None;
        }

        let packet_type = match plaintext[0] {
            TYPE_REAL => PacketType::Real,
            TYPE_CHAFF => PacketType::Chaff,
            TYPE_HEARTBEAT => PacketType::Heartbeat,
            TYPE_ACK => PacketType::Ack,
            _ => return None,
        };

        match packet_type {
            PacketType::Real => {
                if plaintext.len() < 3 {
                    return None;
                }
                let length = u16::from_le_bytes([plaintext[1], plaintext[2]]) as usize;
                if plaintext.len() < 3 + length {
                    return None;
                }
                Some((packet_type, plaintext[3..3 + length].to_vec()))
            }
            _ => Some((packet_type, vec![])),
        }
    }

    /// Calculate next send time with jitter.
    /// Returns milliseconds until next transmission.
    pub fn next_send_delay(&mut self) -> u64 {
        let jitter: i64 = self.rng.gen_range(-(self.config.jitter_ms as i64)..=(self.config.jitter_ms as i64));
        let delay = (self.config.base_interval_ms as i64 + jitter).max(100) as u64;
        delay
    }

    /// Decide whether to send chaff right now.
    /// Call this when there's no real traffic to send.
    pub fn should_send_chaff(&mut self, current_time_ms: u64) -> bool {
        // Reset minute counter if needed
        if current_time_ms - self.minute_start > 60_000 {
            self.minute_start = current_time_ms;
            self.chaff_count_this_minute = 0;
        }

        // Always send if below minimum
        if self.chaff_count_this_minute < self.config.min_chaff_per_minute {
            return true;
        }

        // Otherwise probabilistic
        self.rng.gen_bool(self.config.chaff_probability)
    }

    /// Split a large message into multiple packets.
    pub fn split_message(&mut self, key: &[u8; 32], data: &[u8]) -> Result<Vec<[u8; PACKET_SIZE]>, &'static str> {
        // Account for: 2 bytes length in pad_message + 4 bytes sequence/total
        let chunk_size = MAX_PAYLOAD - 2 - 4;
        let chunks: Vec<&[u8]> = data.chunks(chunk_size).collect();
        let total_chunks = chunks.len() as u16;

        let mut packets = Vec::with_capacity(chunks.len());

        for (i, chunk) in chunks.iter().enumerate() {
            let seq = i as u16;
            let mut payload = Vec::with_capacity(4 + chunk.len());
            payload.extend_from_slice(&seq.to_le_bytes());
            payload.extend_from_slice(&total_chunks.to_le_bytes());
            payload.extend_from_slice(chunk);

            packets.push(self.pad_message(key, &payload)?);
        }

        Ok(packets)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    Real,
    Chaff,
    Heartbeat,
    Ack,
}

/// Timing analyzer for detecting timing attacks.
/// Monitors send/receive patterns for anomalies.
pub struct TimingAnalyzer {
    send_times: Vec<u64>,
    receive_times: Vec<u64>,
    window_size: usize,
}

impl TimingAnalyzer {
    pub fn new(window_size: usize) -> Self {
        Self {
            send_times: Vec::with_capacity(window_size),
            receive_times: Vec::with_capacity(window_size),
            window_size,
        }
    }

    pub fn record_send(&mut self, time_ms: u64) {
        if self.send_times.len() >= self.window_size {
            self.send_times.remove(0);
        }
        self.send_times.push(time_ms);
    }

    pub fn record_receive(&mut self, time_ms: u64) {
        if self.receive_times.len() >= self.window_size {
            self.receive_times.remove(0);
        }
        self.receive_times.push(time_ms);
    }

    /// Check if timing pattern is suspicious (too regular = traffic analysis target)
    pub fn is_pattern_regular(&self) -> bool {
        if self.send_times.len() < 3 {
            return false;
        }

        let mut intervals = Vec::new();
        for i in 1..self.send_times.len() {
            intervals.push(self.send_times[i] - self.send_times[i - 1]);
        }

        // Calculate variance
        let mean: f64 = intervals.iter().sum::<u64>() as f64 / intervals.len() as f64;
        let variance: f64 = intervals.iter()
            .map(|&x| (x as f64 - mean).powi(2))
            .sum::<f64>() / intervals.len() as f64;

        let std_dev = variance.sqrt();

        // If standard deviation is less than 10% of mean, pattern is too regular
        std_dev < mean * 0.1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_unpad_roundtrip() {
        let config = CoverTrafficConfig::default();
        let mut gen = CoverTrafficGenerator::from_seed([42u8; 32], config);
        let key = [1u8; 32];

        let original = b"Hello, this is a secret message!";
        let padded = gen.pad_message(&key, original).unwrap();

        // Verify it's exactly PACKET_SIZE
        assert_eq!(padded.len(), PACKET_SIZE);

        // Unpad and verify
        let (ptype, recovered) = gen.unpad_message(&key, &padded).unwrap();
        assert_eq!(ptype, PacketType::Real);
        assert_eq!(recovered, original);
    }

    #[test]
    fn test_chaff_indistinguishable() {
        let config = CoverTrafficConfig::default();
        let mut gen = CoverTrafficGenerator::from_seed([42u8; 32], config);
        let key = [1u8; 32];

        let real = gen.pad_message(&key, b"Real message").unwrap();
        let chaff = gen.generate_chaff();

        // Both should be same size
        assert_eq!(real.len(), chaff.len());

        // Without key, should both look like random data
        // (We can't actually verify this statistically in a unit test,
        // but we verify the sizes match)
    }

    #[test]
    fn test_split_large_message() {
        let config = CoverTrafficConfig::default();
        let mut gen = CoverTrafficGenerator::from_seed([42u8; 32], config);
        let key = [1u8; 32];

        // Create message larger than one packet
        let large_message = vec![0x42u8; 500];
        let packets = gen.split_message(&key, &large_message).unwrap();

        // Should be split into multiple packets
        assert!(packets.len() > 1);

        // Each packet should be standard size
        for packet in &packets {
            assert_eq!(packet.len(), PACKET_SIZE);
        }
    }

    #[test]
    fn test_timing_jitter() {
        let config = CoverTrafficConfig {
            base_interval_ms: 1000,
            jitter_ms: 500,
            ..Default::default()
        };
        let mut gen = CoverTrafficGenerator::from_seed([42u8; 32], config);

        let mut delays = Vec::new();
        for _ in 0..100 {
            delays.push(gen.next_send_delay());
        }

        // Check delays are within expected range
        for delay in &delays {
            assert!(*delay >= 500);  // base - jitter
            assert!(*delay <= 1500); // base + jitter
        }

        // Check there's actual variance (not all same)
        let first = delays[0];
        let has_variance = delays.iter().any(|&d| d != first);
        assert!(has_variance, "All delays were identical - no jitter!");
    }
}
