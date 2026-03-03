//! Steganographic storage — LSB encoding for deniable encrypted content.
//!
//! Embeds encrypted data in image LSBs with randomized bit distribution.
//! Provides LSB embedding, capacity calculation, and authenticated payloads.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha3::{Digest, Sha3_256};

/// Magic bytes to identify stego content (encrypted, so not visible)
const STEGO_MAGIC: &[u8; 4] = b"STEG";

/// Version byte for format compatibility
const STEGO_VERSION: u8 = 1;

/// Header size: magic(4) + version(1) + length(4) = 9 bytes
const HEADER_SIZE: usize = 9;

/// Size prefix (unencrypted, stores encrypted payload length)
const SIZE_PREFIX_BYTES: usize = 4;

/// Minimum image size for steganography (in pixels)
const MIN_PIXELS: usize = 1024; // 32x32 minimum

/// Bits per pixel we use (1 bit per RGB channel = 3 bits per pixel)
const BITS_PER_PIXEL: usize = 3;

/// Steganography configuration
#[derive(Clone, Debug)]
pub struct StegoConfig {
    /// Use randomized bit positions (harder to detect)
    pub randomize_positions: bool,

    /// Bits per channel to use (1-2, default 1)
    /// Higher = more capacity, but more detectable
    pub bits_per_channel: u8,
}

impl Default for StegoConfig {
    fn default() -> Self {
        Self {
            randomize_positions: true,
            bits_per_channel: 1,
        }
    }
}

/// Calculate steganographic capacity for an image
///
/// @param width Image width in pixels
/// @param height Image height in pixels
/// @param channels Number of color channels (3 for RGB, 4 for RGBA)
/// @param config Steganography configuration
/// @return Maximum bytes that can be hidden
pub fn calculate_capacity(width: usize, height: usize, channels: usize, config: &StegoConfig) -> usize {
    let total_pixels = width * height;
    let usable_channels = channels.min(3); // Don't use alpha channel
    let bits_available = total_pixels * usable_channels * config.bits_per_channel as usize;

    // Account for: size prefix (4) + header (9) + encryption overhead (nonce 12 + tag 16)
    let overhead = SIZE_PREFIX_BYTES + HEADER_SIZE + 12 + 16;

    let bytes_available = bits_available / 8;
    bytes_available.saturating_sub(overhead)
}

/// Embed encrypted data into image pixels
///
/// @param pixels Raw pixel data (RGB or RGBA, row-major order)
/// @param width Image width
/// @param height Image height
/// @param channels 3 for RGB, 4 for RGBA
/// @param key 32-byte encryption key
/// @param data Data to hide
/// @param config Steganography options
/// @return Modified pixel data with embedded payload
pub fn embed(
    pixels: &[u8],
    width: usize,
    height: usize,
    channels: usize,
    key: &[u8; 32],
    data: &[u8],
    config: &StegoConfig,
) -> Result<Vec<u8>, &'static str> {
    // Validate image size
    let total_pixels = width * height;
    if total_pixels < MIN_PIXELS {
        return Err("Image too small for steganography");
    }

    if pixels.len() != width * height * channels {
        return Err("Pixel data size mismatch");
    }

    // Check capacity
    let capacity = calculate_capacity(width, height, channels, config);
    if data.len() > capacity {
        return Err("Data too large for this image");
    }

    // Build header: magic + version + length
    let mut header = Vec::with_capacity(HEADER_SIZE);
    header.extend_from_slice(STEGO_MAGIC);
    header.push(STEGO_VERSION);
    header.extend_from_slice(&(data.len() as u32).to_le_bytes());

    // Combine header + data
    let mut payload = header;
    payload.extend_from_slice(data);

    // Encrypt the payload
    let encrypted = encrypt_payload(key, &payload)?;

    // Prepend size prefix (unencrypted, so we know how much to extract)
    let encrypted_len = encrypted.len() as u32;
    let mut full_payload = Vec::with_capacity(SIZE_PREFIX_BYTES + encrypted.len());
    full_payload.extend_from_slice(&encrypted_len.to_le_bytes());
    full_payload.extend_from_slice(&encrypted);

    // Convert to bits
    let bits = bytes_to_bits(&full_payload);

    // Get bit positions (sequential or randomized)
    let max_positions = total_pixels * channels.min(3);
    let positions: Vec<usize> = if config.randomize_positions {
        generate_random_positions(key, max_positions)
    } else {
        (0..max_positions).collect()
    };

    // Embed bits into image
    let mut output = pixels.to_vec();

    for (bit_idx, &pos) in positions.iter().enumerate() {
        if bit_idx >= bits.len() {
            break;
        }

        // Convert position to pixel location
        let usable_channels = channels.min(3);
        let pixel_idx = pos / usable_channels;
        let channel_idx = pos % usable_channels;
        let byte_idx = pixel_idx * channels + channel_idx;

        if byte_idx >= output.len() {
            return Err("Position out of bounds");
        }

        // Embed single bit in LSB
        if bits[bit_idx] {
            output[byte_idx] |= 1;
        } else {
            output[byte_idx] &= !1;
        }
    }

    Ok(output)
}

/// Extract hidden data from image pixels
///
/// @param pixels Pixel data with embedded content
/// @param width Image width
/// @param height Image height
/// @param channels 3 for RGB, 4 for RGBA
/// @param key 32-byte decryption key
/// @param config Must match config used during embedding
/// @return Extracted data, or None if extraction fails
pub fn extract(
    pixels: &[u8],
    width: usize,
    height: usize,
    channels: usize,
    key: &[u8; 32],
    config: &StegoConfig,
) -> Option<Vec<u8>> {
    let total_pixels = width * height;
    if total_pixels < MIN_PIXELS {
        return None;
    }

    if pixels.len() != width * height * channels {
        return None;
    }

    // Get positions (same as embed for consistency)
    let usable_channels = channels.min(3);
    let max_positions = total_pixels * usable_channels;

    let positions: Vec<usize> = if config.randomize_positions {
        generate_random_positions(key, max_positions)
    } else {
        (0..max_positions).collect()
    };

    // First extract size prefix (4 bytes = 32 bits)
    if positions.len() < SIZE_PREFIX_BYTES * 8 {
        return None;
    }

    let mut size_bits = Vec::with_capacity(SIZE_PREFIX_BYTES * 8);
    for &pos in positions.iter().take(SIZE_PREFIX_BYTES * 8) {
        let pixel_idx = pos / usable_channels;
        let channel_idx = pos % usable_channels;
        let byte_idx = pixel_idx * channels + channel_idx;

        if byte_idx >= pixels.len() {
            return None;
        }

        size_bits.push(pixels[byte_idx] & 1 == 1);
    }

    let size_bytes = bits_to_bytes(&size_bits);
    if size_bytes.len() < 4 {
        return None;
    }

    let encrypted_len = u32::from_le_bytes([
        size_bytes[0], size_bytes[1], size_bytes[2], size_bytes[3]
    ]) as usize;

    // Sanity check on size
    let max_possible = (max_positions / 8).saturating_sub(SIZE_PREFIX_BYTES);
    if encrypted_len == 0 || encrypted_len > max_possible {
        return None;
    }

    // Now extract the encrypted payload
    let total_bits_needed = SIZE_PREFIX_BYTES * 8 + encrypted_len * 8;
    if positions.len() < total_bits_needed {
        return None;
    }

    let mut encrypted_bits = Vec::with_capacity(encrypted_len * 8);
    for &pos in positions.iter().skip(SIZE_PREFIX_BYTES * 8).take(encrypted_len * 8) {
        let pixel_idx = pos / usable_channels;
        let channel_idx = pos % usable_channels;
        let byte_idx = pixel_idx * channels + channel_idx;

        if byte_idx >= pixels.len() {
            return None;
        }

        encrypted_bits.push(pixels[byte_idx] & 1 == 1);
    }

    let encrypted_bytes = bits_to_bytes(&encrypted_bits);

    // Decrypt
    let decrypted = decrypt_payload(key, &encrypted_bytes)?;

    // Validate header
    if decrypted.len() < HEADER_SIZE {
        return None;
    }

    if &decrypted[0..4] != STEGO_MAGIC {
        return None;
    }

    if decrypted[4] != STEGO_VERSION {
        return None; // Version mismatch
    }

    let length = u32::from_le_bytes([
        decrypted[5], decrypted[6], decrypted[7], decrypted[8]
    ]) as usize;

    if decrypted.len() < HEADER_SIZE + length {
        return None;
    }

    Some(decrypted[HEADER_SIZE..HEADER_SIZE + length].to_vec())
}

/// Check if an image likely contains hidden data
///
/// This is a quick heuristic check, not definitive.
/// Returns confidence score 0.0 - 1.0
pub fn detect_stego(pixels: &[u8], width: usize, height: usize, channels: usize) -> f32 {
    if pixels.len() != width * height * channels {
        return 0.0;
    }

    // Chi-square analysis of LSBs
    // Random data should have ~50% 0s and 50% 1s
    let mut ones = 0usize;
    let mut zeros = 0usize;

    for (i, &byte) in pixels.iter().enumerate() {
        // Skip alpha channel
        if channels == 4 && i % 4 == 3 {
            continue;
        }

        if byte & 1 == 1 {
            ones += 1;
        } else {
            zeros += 1;
        }
    }

    let total = ones + zeros;
    if total == 0 {
        return 0.0;
    }

    // Calculate how close to 50/50 the distribution is
    let ratio = ones as f32 / total as f32;
    let deviation = (ratio - 0.5).abs();

    // Natural images tend to have biased LSBs
    // Stego images tend toward 50/50
    // But this is just a heuristic - not reliable
    if deviation < 0.01 {
        0.7 // Very close to 50/50 - suspicious
    } else if deviation < 0.05 {
        0.4 // Somewhat close
    } else {
        0.1 // Looks natural
    }
}

// ============================================================================
// INTERNAL HELPERS
// ============================================================================

fn encrypt_payload(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, &'static str> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| "Invalid key")?;

    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    let mut rng = rand::thread_rng();
    rng.fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|_| "Encryption failed")?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

fn decrypt_payload(key: &[u8; 32], data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 12 + 16 {
        return None; // Too short for nonce + tag
    }

    let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;

    let nonce = Nonce::from_slice(&data[..12]);
    let ciphertext = &data[12..];

    cipher.decrypt(nonce, ciphertext).ok()
}

fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for i in 0..8 {
            bits.push((byte >> (7 - i)) & 1 == 1);
        }
    }
    bits
}

fn bits_to_bytes(bits: &[bool]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity((bits.len() + 7) / 8);
    for chunk in bits.chunks(8) {
        let mut byte = 0u8;
        for (i, &bit) in chunk.iter().enumerate() {
            if bit {
                byte |= 1 << (7 - i);
            }
        }
        bytes.push(byte);
    }
    bytes
}

fn generate_random_positions(key: &[u8; 32], max: usize) -> Vec<usize> {
    // Derive seed from key for deterministic randomization
    let mut hasher = Sha3_256::new();
    hasher.update(key);
    hasher.update(b"stego-positions-v1");
    // Include max in seed so different image sizes get different shuffles
    hasher.update(&(max as u64).to_le_bytes());
    let seed_bytes = hasher.finalize();

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);

    let mut rng = ChaCha20Rng::from_seed(seed);

    // Fisher-Yates shuffle of positions
    let mut positions: Vec<usize> = (0..max).collect();

    for i in (1..positions.len()).rev() {
        let j = rng.gen_range(0..=i);
        positions.swap(i, j);
    }

    positions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capacity_calculation() {
        let config = StegoConfig::default();

        // 100x100 RGB image
        let capacity = calculate_capacity(100, 100, 3, &config);
        // 10000 pixels * 3 channels * 1 bit = 30000 bits = 3750 bytes
        // Minus overhead (4 size prefix + 9 header + 12 nonce + 16 tag = 41)
        assert_eq!(capacity, 3750 - 41);
    }

    #[test]
    fn test_embed_extract_roundtrip() {
        let config = StegoConfig::default();
        let key = [42u8; 32];

        // Create a simple 100x100 RGB image (all gray)
        let width = 100;
        let height = 100;
        let channels = 3;
        let pixels: Vec<u8> = vec![128u8; width * height * channels];

        let secret_data = b"This is a secret message hidden in an image!";

        // Embed
        let stego_pixels = embed(&pixels, width, height, channels, &key, secret_data, &config)
            .expect("Embed should succeed");

        // Verify output size unchanged
        assert_eq!(stego_pixels.len(), pixels.len());

        // Extract
        let recovered = extract(&stego_pixels, width, height, channels, &key, &config)
            .expect("Extract should succeed");

        assert_eq!(recovered, secret_data);
    }

    #[test]
    fn test_wrong_key_fails() {
        let config = StegoConfig::default();
        let key1 = [42u8; 32];
        let key2 = [43u8; 32]; // Different key

        let width = 100;
        let height = 100;
        let channels = 3;
        let pixels: Vec<u8> = vec![128u8; width * height * channels];

        let secret_data = b"Secret";

        let stego_pixels = embed(&pixels, width, height, channels, &key1, secret_data, &config)
            .expect("Embed should succeed");

        // Try to extract with wrong key
        let result = extract(&stego_pixels, width, height, channels, &key2, &config);
        assert!(result.is_none(), "Wrong key should fail to extract");
    }

    #[test]
    fn test_visual_imperceptibility() {
        let config = StegoConfig::default();
        let key = [42u8; 32];

        let width = 100;
        let height = 100;
        let channels = 3;

        // Create gradient image
        let mut pixels: Vec<u8> = Vec::with_capacity(width * height * channels);
        for y in 0..height {
            for x in 0..width {
                pixels.push((x * 255 / width) as u8);     // R
                pixels.push((y * 255 / height) as u8);    // G
                pixels.push(128);                          // B
            }
        }

        let secret_data = b"Hidden message";

        let stego_pixels = embed(&pixels, width, height, channels, &key, secret_data, &config)
            .expect("Embed should succeed");

        // Check that changes are minimal (only LSBs)
        let mut max_diff = 0u8;
        for (orig, stego) in pixels.iter().zip(stego_pixels.iter()) {
            let diff = (*orig as i16 - *stego as i16).unsigned_abs() as u8;
            max_diff = max_diff.max(diff);
        }

        assert!(max_diff <= 1, "Changes should only affect LSB (diff <= 1), got {}", max_diff);
    }

    #[test]
    fn test_rgba_support() {
        let config = StegoConfig::default();
        let key = [42u8; 32];

        let width = 100;
        let height = 100;
        let channels = 4; // RGBA
        let pixels: Vec<u8> = vec![128u8; width * height * channels];

        let secret_data = b"RGBA test";

        let stego_pixels = embed(&pixels, width, height, channels, &key, secret_data, &config)
            .expect("Embed should succeed");

        // Verify alpha channel unchanged
        for i in (3..stego_pixels.len()).step_by(4) {
            assert_eq!(stego_pixels[i], 128, "Alpha channel should be unchanged");
        }

        let recovered = extract(&stego_pixels, width, height, channels, &key, &config)
            .expect("Extract should succeed");

        assert_eq!(recovered, secret_data);
    }

    #[test]
    fn test_randomized_positions() {
        // Test that randomized positions are deterministic (same key = same positions)
        let key = [42u8; 32];
        let pos1 = generate_random_positions(&key, 1000);
        let pos2 = generate_random_positions(&key, 1000);
        assert_eq!(pos1, pos2, "Same key should produce same positions");

        // Different key = different positions
        let key2 = [43u8; 32];
        let pos3 = generate_random_positions(&key2, 1000);
        assert_ne!(pos1, pos3, "Different key should produce different positions");
    }
}
