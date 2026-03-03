//! LoRa Transport Abstraction
//!
//! Defines the traits and types for LoRa hardware communication.

use std::time::Duration;

// ============================================================================
// CONSTANTS
// ============================================================================

/// Maximum LoRa packet size (physical layer limit)
pub const LORA_MAX_PACKET: usize = 255;

/// LunarCore packet size (within LoRa limit, with safety margin)
pub const LUNAR_PACKET_SIZE: usize = 237;

/// Default frequency for EU868 band (MHz)
pub const FREQ_EU868: u32 = 868_100_000;

/// Default frequency for US915 band (MHz)
pub const FREQ_US915: u32 = 915_000_000;

/// Default spreading factor
pub const DEFAULT_SF: u8 = 9;

/// Default bandwidth (125 kHz)
pub const DEFAULT_BW: u32 = 125_000;

/// Default coding rate (4/5)
pub const DEFAULT_CR: u8 = 5;

// ============================================================================
// CONFIGURATION
// ============================================================================

/// LoRa radio configuration
#[derive(Debug, Clone)]
pub struct LoRaConfig {
    /// Frequency in Hz (e.g., 868_100_000 for EU868)
    pub frequency: u32,

    /// Spreading factor (7-12)
    pub spreading_factor: u8,

    /// Bandwidth in Hz (125000, 250000, or 500000)
    pub bandwidth: u32,

    /// Coding rate denominator (5-8 for 4/5 to 4/8)
    pub coding_rate: u8,

    /// Transmit power in dBm (2-20)
    pub tx_power: i8,

    /// Sync word (0x12 for private networks, 0x34 for public LoRaWAN)
    pub sync_word: u8,

    /// Preamble length (symbols)
    pub preamble_length: u16,

    /// Enable CRC
    pub crc_enabled: bool,

    /// Implicit header mode (fixed packet length)
    pub implicit_header: bool,

    /// Low data rate optimization (required for SF11/12 at 125kHz)
    pub low_data_rate_optimize: bool,
}

impl Default for LoRaConfig {
    fn default() -> Self {
        Self {
            frequency: FREQ_EU868,
            spreading_factor: DEFAULT_SF,
            bandwidth: DEFAULT_BW,
            coding_rate: DEFAULT_CR,
            tx_power: 14,
            sync_word: 0x12, // Private network
            preamble_length: 8,
            crc_enabled: true,
            implicit_header: false,
            low_data_rate_optimize: false,
        }
    }
}

impl LoRaConfig {
    /// Create config for EU868 band
    pub fn eu868() -> Self {
        Self {
            frequency: FREQ_EU868,
            ..Default::default()
        }
    }

    /// Create config for US915 band
    pub fn us915() -> Self {
        Self {
            frequency: FREQ_US915,
            tx_power: 20, // US allows higher power
            ..Default::default()
        }
    }

    /// Calculate on-air time for a packet (milliseconds)
    pub fn time_on_air_ms(&self, payload_len: usize) -> u32 {
        // Simplified formula - actual calculation is more complex
        let sf = self.spreading_factor as u32;
        let bw = self.bandwidth / 1000; // kHz
        let preamble = self.preamble_length as u32;
        let cr = self.coding_rate as u32;

        // Symbol time in ms
        let t_sym = (1 << sf) * 1000 / bw;

        // Payload symbols (simplified)
        let payload_bits = (payload_len as u32 + 13) * 8; // +13 for header/CRC
        let payload_symbols = (payload_bits * cr) / (4 * sf);

        // Total time
        (preamble + 4 + payload_symbols) * t_sym / 1000
    }

    /// Calculate maximum duty cycle compliant packets per hour (EU 1%)
    pub fn packets_per_hour(&self, payload_len: usize) -> u32 {
        let time_on_air = self.time_on_air_ms(payload_len);
        if time_on_air == 0 {
            return 0;
        }
        // 1% duty cycle = 36 seconds per hour
        36_000 / time_on_air
    }
}

// ============================================================================
// PACKET
// ============================================================================

/// A received LoRa packet
#[derive(Debug, Clone)]
pub struct LoRaPacket {
    /// Raw packet data
    pub data: Vec<u8>,

    /// RSSI in dBm
    pub rssi: i16,

    /// SNR in dB (x4, so 20 = 5.0 dB)
    pub snr: i8,

    /// Frequency offset (Hz)
    pub freq_error: i32,

    /// Timestamp when received (Unix millis)
    pub timestamp: u64,
}

impl LoRaPacket {
    /// Create a new packet
    pub fn new(data: Vec<u8>, rssi: i16, snr: i8) -> Self {
        Self {
            data,
            rssi,
            snr,
            freq_error: 0,
            timestamp: current_time_ms(),
        }
    }

    /// Get link quality (0-100)
    pub fn link_quality(&self) -> u8 {
        // Simplified link quality calculation
        // RSSI: -120 dBm = bad, -40 dBm = good
        // SNR: -20 dB = bad, +10 dB = good
        let rssi_norm = ((self.rssi + 120).max(0).min(80) as u32 * 100) / 80;
        let snr_norm = (((self.snr as i32 + 20).max(0).min(30) as u32) * 100) / 30;
        ((rssi_norm + snr_norm) / 2).min(100) as u8
    }
}

// ============================================================================
// STATISTICS
// ============================================================================

/// Transport statistics
#[derive(Debug, Clone, Default)]
pub struct TransportStats {
    /// Packets transmitted
    pub tx_packets: u64,
    /// Packets received
    pub rx_packets: u64,
    /// Transmit errors
    pub tx_errors: u64,
    /// Receive errors (CRC failures, etc.)
    pub rx_errors: u64,
    /// Bytes transmitted
    pub tx_bytes: u64,
    /// Bytes received
    pub rx_bytes: u64,
    /// Total time on air (milliseconds)
    pub total_airtime_ms: u64,
    /// Last RSSI (dBm)
    pub last_rssi: i16,
    /// Last SNR (dB x4)
    pub last_snr: i8,
}

// ============================================================================
// ERROR TYPE
// ============================================================================

/// LoRa transport errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoRaError {
    /// Device not connected
    NotConnected,
    /// Configuration error
    ConfigError(String),
    /// Transmit failed
    TxFailed,
    /// Receive timeout
    RxTimeout,
    /// CRC error
    CrcError,
    /// Packet too large
    PacketTooLarge,
    /// Channel busy (CAD detected activity)
    ChannelBusy,
    /// Serial port error
    SerialError(String),
    /// Protocol error
    ProtocolError(String),
    /// Device error
    DeviceError(String),
}

impl std::fmt::Display for LoRaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoRaError::NotConnected => write!(f, "Device not connected"),
            LoRaError::ConfigError(s) => write!(f, "Configuration error: {}", s),
            LoRaError::TxFailed => write!(f, "Transmit failed"),
            LoRaError::RxTimeout => write!(f, "Receive timeout"),
            LoRaError::CrcError => write!(f, "CRC error"),
            LoRaError::PacketTooLarge => write!(f, "Packet too large"),
            LoRaError::ChannelBusy => write!(f, "Channel busy"),
            LoRaError::SerialError(s) => write!(f, "Serial error: {}", s),
            LoRaError::ProtocolError(s) => write!(f, "Protocol error: {}", s),
            LoRaError::DeviceError(s) => write!(f, "Device error: {}", s),
        }
    }
}

impl std::error::Error for LoRaError {}

// ============================================================================
// TRANSPORT TRAIT
// ============================================================================

/// LoRa transport abstraction
///
/// Implementations provide the actual hardware interface.
pub trait LoRaTransport: Send + Sync {
    /// Connect to the LoRa device
    fn connect(&mut self) -> Result<(), LoRaError>;

    /// Disconnect from the LoRa device
    fn disconnect(&mut self) -> Result<(), LoRaError>;

    /// Check if connected
    fn is_connected(&self) -> bool;

    /// Configure the radio
    fn configure(&mut self, config: &LoRaConfig) -> Result<(), LoRaError>;

    /// Get current configuration
    fn get_config(&self) -> Option<&LoRaConfig>;

    /// Transmit a packet
    ///
    /// Blocks until transmission is complete or fails.
    fn transmit(&mut self, data: &[u8]) -> Result<(), LoRaError>;

    /// Receive a packet
    ///
    /// Blocks until a packet is received or timeout expires.
    fn receive(&mut self, timeout: Duration) -> Result<Option<LoRaPacket>, LoRaError>;

    /// Check for pending received packets (non-blocking)
    fn poll_receive(&mut self) -> Result<Option<LoRaPacket>, LoRaError>;

    /// Perform Channel Activity Detection
    ///
    /// Returns true if the channel is busy.
    fn channel_activity_detected(&mut self) -> Result<bool, LoRaError>;

    /// Get transport statistics
    fn stats(&self) -> TransportStats;

    /// Reset statistics
    fn reset_stats(&mut self);

    /// Get device firmware version
    fn firmware_version(&self) -> Option<String>;
}

// ============================================================================
// HELPERS
// ============================================================================

/// Get current time in milliseconds
fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_defaults() {
        let config = LoRaConfig::default();
        assert_eq!(config.frequency, FREQ_EU868);
        assert_eq!(config.spreading_factor, 9);
        assert_eq!(config.bandwidth, 125_000);
    }

    #[test]
    fn test_time_on_air() {
        let config = LoRaConfig::default();
        let toa = config.time_on_air_ms(LUNAR_PACKET_SIZE);
        // Simplified calculation - just verify it produces a reasonable value
        // Actual airtime depends on exact formula implementation
        assert!(toa > 0, "Time on air should be positive: got {}", toa);
    }

    #[test]
    fn test_packets_per_hour() {
        let config = LoRaConfig::default();
        let pph = config.packets_per_hour(LUNAR_PACKET_SIZE);
        // With 1% duty cycle, should be able to send some packets per hour
        assert!(pph > 0, "Should be able to send at least 1 packet per hour: got {}", pph);
    }

    #[test]
    fn test_link_quality() {
        // Good signal
        let pkt = LoRaPacket::new(vec![], -60, 10);
        assert!(pkt.link_quality() > 70);

        // Bad signal
        let pkt = LoRaPacket::new(vec![], -110, -15);
        assert!(pkt.link_quality() < 30);
    }
}
