//! Serial Protocol for ESP32 LoRa Communication
//!
//! Defines the framing protocol for USB/Serial communication between
//! Android and ESP32.
//!
//! ## Frame Format
//!
//! ```text
//! +------+------+--------+------+--------+-----+------+
//! | SYNC | LEN  |  CMD   | SEQ  |  DATA  | CRC | END  |
//! +------+------+--------+------+--------+-----+------+
//!   2B     2B     1B       1B    0-255B   2B    1B
//! ```
//!
//! - SYNC: 0xAA 0x55 (magic bytes)
//! - LEN: Little-endian u16 (data length only)
//! - CMD: Command byte
//! - SEQ: Sequence number (for matching responses)
//! - DATA: Command-specific payload
//! - CRC: CRC-16 over CMD+SEQ+DATA
//! - END: 0x0D (carriage return)

use super::transport::*;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

// ============================================================================
// PROTOCOL CONSTANTS
// ============================================================================

/// Frame sync bytes
const SYNC_BYTES: [u8; 2] = [0xAA, 0x55];

/// Frame end byte
const END_BYTE: u8 = 0x0D;

/// Maximum frame size
const MAX_FRAME_SIZE: usize = 300;

/// Default baud rate
pub const DEFAULT_BAUD_RATE: u32 = 115200;

// ============================================================================
// COMMANDS
// ============================================================================

/// Serial protocol commands
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    /// Ping/heartbeat
    Ping = 0x01,
    /// Pong response
    Pong = 0x02,
    /// Configure radio
    Configure = 0x10,
    /// Configuration acknowledgment
    ConfigAck = 0x11,
    /// Transmit packet
    Transmit = 0x20,
    /// Transmit done
    TxDone = 0x21,
    /// Transmit error
    TxError = 0x22,
    /// Receive packet
    Receive = 0x30,
    /// Get stats
    GetStats = 0x40,
    /// Stats response
    StatsResponse = 0x41,
    /// Channel activity detection
    Cad = 0x50,
    /// CAD result
    CadResult = 0x51,
    /// Reset device
    Reset = 0xF0,
    /// Firmware version query
    Version = 0xF1,
    /// Version response
    VersionResponse = 0xF2,
    /// Error response
    Error = 0xFF,
}

impl Command {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Command::Ping),
            0x02 => Some(Command::Pong),
            0x10 => Some(Command::Configure),
            0x11 => Some(Command::ConfigAck),
            0x20 => Some(Command::Transmit),
            0x21 => Some(Command::TxDone),
            0x22 => Some(Command::TxError),
            0x30 => Some(Command::Receive),
            0x40 => Some(Command::GetStats),
            0x41 => Some(Command::StatsResponse),
            0x50 => Some(Command::Cad),
            0x51 => Some(Command::CadResult),
            0xF0 => Some(Command::Reset),
            0xF1 => Some(Command::Version),
            0xF2 => Some(Command::VersionResponse),
            0xFF => Some(Command::Error),
            _ => None,
        }
    }
}

// ============================================================================
// FRAME
// ============================================================================

/// A protocol frame
#[derive(Debug, Clone)]
pub struct Frame {
    pub command: Command,
    pub sequence: u8,
    pub data: Vec<u8>,
}

impl Frame {
    /// Create a new frame
    pub fn new(command: Command, sequence: u8, data: Vec<u8>) -> Self {
        Self { command, sequence, data }
    }

    /// Encode frame to bytes
    pub fn encode(&self) -> Vec<u8> {
        let data_len = self.data.len();
        let mut frame = Vec::with_capacity(9 + data_len);

        // Sync bytes
        frame.extend_from_slice(&SYNC_BYTES);

        // Length (data only)
        frame.extend_from_slice(&(data_len as u16).to_le_bytes());

        // Command and sequence
        frame.push(self.command as u8);
        frame.push(self.sequence);

        // Data
        frame.extend_from_slice(&self.data);

        // CRC-16 over cmd+seq+data
        let crc = crc16(&frame[4..]);
        frame.extend_from_slice(&crc.to_le_bytes());

        // End byte
        frame.push(END_BYTE);

        frame
    }

    /// Decode frame from bytes
    pub fn decode(bytes: &[u8]) -> Result<Self, LoRaError> {
        if bytes.len() < 9 {
            return Err(LoRaError::ProtocolError("Frame too short".into()));
        }

        // Check sync
        if bytes[0] != SYNC_BYTES[0] || bytes[1] != SYNC_BYTES[1] {
            return Err(LoRaError::ProtocolError("Invalid sync".into()));
        }

        // Get length
        let data_len = u16::from_le_bytes([bytes[2], bytes[3]]) as usize;
        let expected_len = 9 + data_len;

        if bytes.len() < expected_len {
            return Err(LoRaError::ProtocolError("Incomplete frame".into()));
        }

        // Check end byte
        if bytes[expected_len - 1] != END_BYTE {
            return Err(LoRaError::ProtocolError("Invalid end byte".into()));
        }

        // Verify CRC
        let crc_offset = 6 + data_len;
        let received_crc = u16::from_le_bytes([bytes[crc_offset], bytes[crc_offset + 1]]);
        let calculated_crc = crc16(&bytes[4..crc_offset]);

        if received_crc != calculated_crc {
            return Err(LoRaError::CrcError);
        }

        // Parse command
        let command = Command::from_byte(bytes[4])
            .ok_or_else(|| LoRaError::ProtocolError("Unknown command".into()))?;

        let sequence = bytes[5];
        let data = bytes[6..6 + data_len].to_vec();

        Ok(Frame { command, sequence, data })
    }
}

// ============================================================================
// SERIAL CONFIG
// ============================================================================

/// Serial port configuration
#[derive(Debug, Clone)]
pub struct SerialConfig {
    /// Port name (e.g., "/dev/ttyUSB0" or "COM3")
    pub port: String,
    /// Baud rate
    pub baud_rate: u32,
    /// Read timeout
    pub read_timeout: Duration,
    /// Write timeout
    pub write_timeout: Duration,
}

impl Default for SerialConfig {
    fn default() -> Self {
        Self {
            port: String::new(),
            baud_rate: DEFAULT_BAUD_RATE,
            read_timeout: Duration::from_millis(1000),
            write_timeout: Duration::from_millis(1000),
        }
    }
}

// ============================================================================
// SERIAL TRANSPORT
// ============================================================================

/// Serial transport implementation
///
/// Note: Actual serial I/O requires platform-specific implementation.
/// This provides the protocol layer - the actual port I/O is abstracted.
pub struct SerialTransport {
    /// Serial configuration
    serial_config: SerialConfig,
    /// LoRa configuration
    lora_config: Option<LoRaConfig>,
    /// Connected state
    connected: bool,
    /// Sequence counter
    sequence: u8,
    /// Statistics
    stats: TransportStats,
    /// Firmware version
    firmware_version: Option<String>,
    /// Receive queue (for poll_receive)
    rx_queue: VecDeque<LoRaPacket>,
    /// Raw bytes for serial I/O (platform provides actual I/O)
    tx_buffer: Vec<u8>,
    rx_buffer: Vec<u8>,
}

impl SerialTransport {
    /// Create a new serial transport
    pub fn new(config: SerialConfig) -> Self {
        Self {
            serial_config: config,
            lora_config: None,
            connected: false,
            sequence: 0,
            stats: TransportStats::default(),
            firmware_version: None,
            rx_queue: VecDeque::new(),
            tx_buffer: Vec::new(),
            rx_buffer: Vec::with_capacity(MAX_FRAME_SIZE),
        }
    }

    /// Get next sequence number
    fn next_sequence(&mut self) -> u8 {
        let seq = self.sequence;
        self.sequence = self.sequence.wrapping_add(1);
        seq
    }

    /// Build a transmit command frame
    pub fn build_transmit_frame(&mut self, data: &[u8]) -> Vec<u8> {
        let seq = self.next_sequence();
        let frame = Frame::new(Command::Transmit, seq, data.to_vec());
        frame.encode()
    }

    /// Build a configure command frame
    pub fn build_configure_frame(&mut self, config: &LoRaConfig) -> Vec<u8> {
        let seq = self.next_sequence();
        let mut data = Vec::with_capacity(16);

        // Encode config as binary
        data.extend_from_slice(&config.frequency.to_le_bytes());
        data.push(config.spreading_factor);
        data.extend_from_slice(&(config.bandwidth / 1000).to_le_bytes()[..2]); // kHz as u16
        data.push(config.coding_rate);
        data.push(config.tx_power as u8);
        data.push(config.sync_word);
        data.extend_from_slice(&config.preamble_length.to_le_bytes());

        let mut flags = 0u8;
        if config.crc_enabled { flags |= 0x01; }
        if config.implicit_header { flags |= 0x02; }
        if config.low_data_rate_optimize { flags |= 0x04; }
        data.push(flags);

        Frame::new(Command::Configure, seq, data).encode()
    }

    /// Build a ping frame
    pub fn build_ping_frame(&mut self) -> Vec<u8> {
        let seq = self.next_sequence();
        Frame::new(Command::Ping, seq, vec![]).encode()
    }

    /// Build a version query frame
    pub fn build_version_frame(&mut self) -> Vec<u8> {
        let seq = self.next_sequence();
        Frame::new(Command::Version, seq, vec![]).encode()
    }

    /// Build a CAD request frame
    pub fn build_cad_frame(&mut self) -> Vec<u8> {
        let seq = self.next_sequence();
        Frame::new(Command::Cad, seq, vec![]).encode()
    }

    /// Build a stats request frame
    pub fn build_stats_frame(&mut self) -> Vec<u8> {
        let seq = self.next_sequence();
        Frame::new(Command::GetStats, seq, vec![]).encode()
    }

    /// Parse a received frame
    pub fn parse_response(&mut self, data: &[u8]) -> Result<Frame, LoRaError> {
        Frame::decode(data)
    }

    /// Process a received frame
    pub fn process_frame(&mut self, frame: &Frame) -> Result<(), LoRaError> {
        match frame.command {
            Command::Receive => {
                // Parse received packet
                if frame.data.len() >= 4 {
                    let rssi = i16::from_le_bytes([frame.data[0], frame.data[1]]);
                    let snr = frame.data[2] as i8;
                    let pkt_data = frame.data[4..].to_vec();

                    let packet = LoRaPacket::new(pkt_data, rssi, snr);
                    self.rx_queue.push_back(packet);
                    self.stats.rx_packets += 1;
                    self.stats.rx_bytes += frame.data.len() as u64 - 4;
                    self.stats.last_rssi = rssi;
                    self.stats.last_snr = snr;
                }
            }
            Command::TxDone => {
                self.stats.tx_packets += 1;
            }
            Command::TxError => {
                self.stats.tx_errors += 1;
                return Err(LoRaError::TxFailed);
            }
            Command::VersionResponse => {
                if !frame.data.is_empty() {
                    self.firmware_version = String::from_utf8(frame.data.clone()).ok();
                }
            }
            Command::StatsResponse => {
                // Parse stats from device (if needed)
            }
            Command::Error => {
                let msg = String::from_utf8_lossy(&frame.data).to_string();
                return Err(LoRaError::DeviceError(msg));
            }
            _ => {}
        }
        Ok(())
    }

    /// Get pending transmit data
    pub fn get_tx_data(&mut self) -> Option<Vec<u8>> {
        if self.tx_buffer.is_empty() {
            None
        } else {
            Some(std::mem::take(&mut self.tx_buffer))
        }
    }

    /// Feed received serial data
    pub fn feed_rx_data(&mut self, data: &[u8]) -> Result<Vec<Frame>, LoRaError> {
        self.rx_buffer.extend_from_slice(data);

        let mut frames = Vec::new();

        // Try to parse complete frames
        while self.rx_buffer.len() >= 9 {
            // Find sync bytes
            let sync_pos = self.rx_buffer.windows(2)
                .position(|w| w == SYNC_BYTES);

            match sync_pos {
                Some(0) => {
                    // Sync at start, try to parse
                    if self.rx_buffer.len() >= 4 {
                        let data_len = u16::from_le_bytes([
                            self.rx_buffer[2],
                            self.rx_buffer[3]
                        ]) as usize;

                        let frame_len = 9 + data_len;

                        if self.rx_buffer.len() >= frame_len {
                            let frame_bytes: Vec<u8> = self.rx_buffer.drain(..frame_len).collect();
                            match Frame::decode(&frame_bytes) {
                                Ok(frame) => {
                                    self.process_frame(&frame)?;
                                    frames.push(frame);
                                }
                                Err(e) => {
                                    // Skip invalid frame
                                    eprintln!("Frame decode error: {:?}", e);
                                }
                            }
                        } else {
                            // Need more data
                            break;
                        }
                    } else {
                        // Need more data
                        break;
                    }
                }
                Some(pos) => {
                    // Discard garbage before sync
                    self.rx_buffer.drain(..pos);
                }
                None => {
                    // No sync found, keep last byte (might be start of sync)
                    if self.rx_buffer.len() > 1 {
                        let last = self.rx_buffer.pop().unwrap();
                        self.rx_buffer.clear();
                        self.rx_buffer.push(last);
                    }
                    break;
                }
            }
        }

        Ok(frames)
    }
}

impl LoRaTransport for SerialTransport {
    fn connect(&mut self) -> Result<(), LoRaError> {
        // Platform-specific serial port opening happens here
        // For now, just mark as connected
        self.connected = true;

        // Send ping to verify connection
        self.tx_buffer = self.build_ping_frame();

        Ok(())
    }

    fn disconnect(&mut self) -> Result<(), LoRaError> {
        self.connected = false;
        Ok(())
    }

    fn is_connected(&self) -> bool {
        self.connected
    }

    fn configure(&mut self, config: &LoRaConfig) -> Result<(), LoRaError> {
        if !self.connected {
            return Err(LoRaError::NotConnected);
        }

        self.tx_buffer = self.build_configure_frame(config);
        self.lora_config = Some(config.clone());

        Ok(())
    }

    fn get_config(&self) -> Option<&LoRaConfig> {
        self.lora_config.as_ref()
    }

    fn transmit(&mut self, data: &[u8]) -> Result<(), LoRaError> {
        if !self.connected {
            return Err(LoRaError::NotConnected);
        }

        if data.len() > LUNAR_PACKET_SIZE {
            return Err(LoRaError::PacketTooLarge);
        }

        self.tx_buffer = self.build_transmit_frame(data);
        self.stats.tx_bytes += data.len() as u64;

        // Estimate airtime
        if let Some(config) = &self.lora_config {
            self.stats.total_airtime_ms += config.time_on_air_ms(data.len()) as u64;
        }

        Ok(())
    }

    fn receive(&mut self, timeout: Duration) -> Result<Option<LoRaPacket>, LoRaError> {
        if !self.connected {
            return Err(LoRaError::NotConnected);
        }

        // Check queue first
        if let Some(pkt) = self.rx_queue.pop_front() {
            return Ok(Some(pkt));
        }

        // Would block waiting for data in real implementation
        Ok(None)
    }

    fn poll_receive(&mut self) -> Result<Option<LoRaPacket>, LoRaError> {
        Ok(self.rx_queue.pop_front())
    }

    fn channel_activity_detected(&mut self) -> Result<bool, LoRaError> {
        if !self.connected {
            return Err(LoRaError::NotConnected);
        }

        self.tx_buffer = self.build_cad_frame();
        // Would wait for CadResult response
        Ok(false)
    }

    fn stats(&self) -> TransportStats {
        self.stats.clone()
    }

    fn reset_stats(&mut self) {
        self.stats = TransportStats::default();
    }

    fn firmware_version(&self) -> Option<String> {
        self.firmware_version.clone()
    }
}

// ============================================================================
// CRC
// ============================================================================

/// CRC-16 calculation (CRC-16-CCITT)
fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for byte in data {
        crc ^= (*byte as u16) << 8;
        for _ in 0..8 {
            if (crc & 0x8000) != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_encode_decode() {
        let frame = Frame::new(Command::Ping, 42, vec![1, 2, 3]);
        let encoded = frame.encode();
        let decoded = Frame::decode(&encoded).unwrap();

        assert_eq!(decoded.command, Command::Ping);
        assert_eq!(decoded.sequence, 42);
        assert_eq!(decoded.data, vec![1, 2, 3]);
    }

    #[test]
    fn test_frame_empty_data() {
        let frame = Frame::new(Command::Pong, 0, vec![]);
        let encoded = frame.encode();
        let decoded = Frame::decode(&encoded).unwrap();

        assert_eq!(decoded.command, Command::Pong);
        assert_eq!(decoded.data.len(), 0);
    }

    #[test]
    fn test_crc_calculation() {
        let data = b"Hello";
        let crc = crc16(data);
        assert_ne!(crc, 0); // Just verify it runs
    }

    #[test]
    fn test_serial_transport_build_frames() {
        let config = SerialConfig::default();
        let mut transport = SerialTransport::new(config);

        let ping = transport.build_ping_frame();
        assert!(ping.len() >= 9);
        assert_eq!(ping[0], 0xAA);
        assert_eq!(ping[1], 0x55);
    }

    #[test]
    fn test_feed_rx_data() {
        let config = SerialConfig::default();
        let mut transport = SerialTransport::new(config);

        // Create a pong frame
        let frame = Frame::new(Command::Pong, 1, vec![]);
        let encoded = frame.encode();

        // Feed it
        let frames = transport.feed_rx_data(&encoded).unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].command, Command::Pong);
    }
}
