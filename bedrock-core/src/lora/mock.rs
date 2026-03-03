//! Mock LoRa Transport for Testing
//!
//! Provides a simulated LoRa transport that can be used for:
//! - Unit testing
//! - Integration testing
//! - Protocol development without hardware

use super::transport::*;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ============================================================================
// MOCK TRANSPORT
// ============================================================================

/// Mock LoRa transport for testing
///
/// Simulates LoRa transmission with configurable behavior.
pub struct MockTransport {
    /// Connected state
    connected: bool,
    /// Radio configuration
    config: Option<LoRaConfig>,
    /// Statistics
    stats: TransportStats,
    /// Receive queue (packets to be "received")
    rx_queue: VecDeque<LoRaPacket>,
    /// Transmit history (packets that were "sent")
    tx_history: Vec<Vec<u8>>,
    /// Simulated channel busy state
    channel_busy: bool,
    /// Simulated failure mode
    fail_mode: MockFailMode,
    /// Optional peer transport for loopback testing
    peer: Option<Arc<Mutex<MockTransport>>>,
}

/// Failure modes for testing error handling
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockFailMode {
    /// Normal operation
    None,
    /// All transmits fail
    TxAlwaysFails,
    /// All receives timeout
    RxAlwaysTimeout,
    /// Random failures (50%)
    RandomFailures,
    /// CRC errors on receive
    CrcErrors,
}

impl Default for MockTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl MockTransport {
    /// Create a new mock transport
    pub fn new() -> Self {
        Self {
            connected: false,
            config: None,
            stats: TransportStats::default(),
            rx_queue: VecDeque::new(),
            tx_history: Vec::new(),
            channel_busy: false,
            fail_mode: MockFailMode::None,
            peer: None,
        }
    }

    /// Create a connected pair of mock transports for bidirectional testing
    pub fn create_pair() -> (Arc<Mutex<Self>>, Arc<Mutex<Self>>) {
        let a = Arc::new(Mutex::new(Self::new()));
        let b = Arc::new(Mutex::new(Self::new()));

        a.lock().unwrap().peer = Some(Arc::clone(&b));
        b.lock().unwrap().peer = Some(Arc::clone(&a));

        (a, b)
    }

    /// Set failure mode
    pub fn set_fail_mode(&mut self, mode: MockFailMode) {
        self.fail_mode = mode;
    }

    /// Set channel busy state
    pub fn set_channel_busy(&mut self, busy: bool) {
        self.channel_busy = busy;
    }

    /// Inject a packet to be received
    pub fn inject_packet(&mut self, data: Vec<u8>, rssi: i16, snr: i8) {
        let packet = LoRaPacket::new(data, rssi, snr);
        self.rx_queue.push_back(packet);
    }

    /// Get transmitted packets
    pub fn get_tx_history(&self) -> &[Vec<u8>] {
        &self.tx_history
    }

    /// Clear transmit history
    pub fn clear_tx_history(&mut self) {
        self.tx_history.clear();
    }

    /// Check if should fail based on mode
    fn should_fail_tx(&self) -> bool {
        match self.fail_mode {
            MockFailMode::TxAlwaysFails => true,
            MockFailMode::RandomFailures => rand_bool(),
            _ => false,
        }
    }

    fn should_fail_rx(&self) -> bool {
        match self.fail_mode {
            MockFailMode::RxAlwaysTimeout => true,
            MockFailMode::RandomFailures => rand_bool(),
            _ => false,
        }
    }
}

impl LoRaTransport for MockTransport {
    fn connect(&mut self) -> Result<(), LoRaError> {
        self.connected = true;
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
        self.config = Some(config.clone());
        Ok(())
    }

    fn get_config(&self) -> Option<&LoRaConfig> {
        self.config.as_ref()
    }

    fn transmit(&mut self, data: &[u8]) -> Result<(), LoRaError> {
        if !self.connected {
            return Err(LoRaError::NotConnected);
        }

        if data.len() > LUNAR_PACKET_SIZE {
            return Err(LoRaError::PacketTooLarge);
        }

        if self.should_fail_tx() {
            self.stats.tx_errors += 1;
            return Err(LoRaError::TxFailed);
        }

        // Record the transmission
        self.tx_history.push(data.to_vec());
        self.stats.tx_packets += 1;
        self.stats.tx_bytes += data.len() as u64;

        // If we have a peer, deliver the packet to them
        if let Some(peer) = &self.peer {
            if let Ok(mut peer_guard) = peer.lock() {
                // Simulate radio propagation with typical RSSI/SNR
                peer_guard.inject_packet(data.to_vec(), -80, 8);
            }
        }

        // Estimate airtime
        if let Some(config) = &self.config {
            self.stats.total_airtime_ms += config.time_on_air_ms(data.len()) as u64;
        }

        Ok(())
    }

    fn receive(&mut self, _timeout: Duration) -> Result<Option<LoRaPacket>, LoRaError> {
        if !self.connected {
            return Err(LoRaError::NotConnected);
        }

        if self.should_fail_rx() {
            return Err(LoRaError::RxTimeout);
        }

        if self.fail_mode == MockFailMode::CrcErrors {
            if let Some(_) = self.rx_queue.pop_front() {
                self.stats.rx_errors += 1;
                return Err(LoRaError::CrcError);
            }
        }

        if let Some(pkt) = self.rx_queue.pop_front() {
            self.stats.rx_packets += 1;
            self.stats.rx_bytes += pkt.data.len() as u64;
            self.stats.last_rssi = pkt.rssi;
            self.stats.last_snr = pkt.snr;
            return Ok(Some(pkt));
        }

        Ok(None)
    }

    fn poll_receive(&mut self) -> Result<Option<LoRaPacket>, LoRaError> {
        self.receive(Duration::ZERO)
    }

    fn channel_activity_detected(&mut self) -> Result<bool, LoRaError> {
        if !self.connected {
            return Err(LoRaError::NotConnected);
        }
        Ok(self.channel_busy)
    }

    fn stats(&self) -> TransportStats {
        self.stats.clone()
    }

    fn reset_stats(&mut self) {
        self.stats = TransportStats::default();
    }

    fn firmware_version(&self) -> Option<String> {
        Some("MockTransport v1.0".to_string())
    }
}

// Simple random bool for testing
fn rand_bool() -> bool {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    nanos % 2 == 0
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mock_connect_disconnect() {
        let mut transport = MockTransport::new();

        assert!(!transport.is_connected());
        transport.connect().unwrap();
        assert!(transport.is_connected());
        transport.disconnect().unwrap();
        assert!(!transport.is_connected());
    }

    #[test]
    fn test_mock_configure() {
        let mut transport = MockTransport::new();
        transport.connect().unwrap();

        let config = LoRaConfig::default();
        transport.configure(&config).unwrap();

        assert!(transport.get_config().is_some());
    }

    #[test]
    fn test_mock_transmit() {
        let mut transport = MockTransport::new();
        transport.connect().unwrap();

        let data = b"Hello, LoRa!";
        transport.transmit(data).unwrap();

        assert_eq!(transport.get_tx_history().len(), 1);
        assert_eq!(transport.get_tx_history()[0], data);
        assert_eq!(transport.stats().tx_packets, 1);
    }

    #[test]
    fn test_mock_receive() {
        let mut transport = MockTransport::new();
        transport.connect().unwrap();

        // Inject a packet
        transport.inject_packet(b"Test packet".to_vec(), -70, 10);

        // Receive it
        let pkt = transport.receive(Duration::from_millis(100)).unwrap().unwrap();
        assert_eq!(pkt.data, b"Test packet");
        assert_eq!(pkt.rssi, -70);
        assert_eq!(pkt.snr, 10);
    }

    #[test]
    fn test_mock_pair_communication() {
        let (a, b) = MockTransport::create_pair();

        // Connect both
        a.lock().unwrap().connect().unwrap();
        b.lock().unwrap().connect().unwrap();

        // A sends to B
        let message = b"Hello from A";
        a.lock().unwrap().transmit(message).unwrap();

        // B should receive it
        let pkt = b.lock().unwrap()
            .receive(Duration::from_millis(100))
            .unwrap()
            .unwrap();

        assert_eq!(pkt.data, message);
    }

    #[test]
    fn test_mock_fail_mode() {
        let mut transport = MockTransport::new();
        transport.connect().unwrap();
        transport.set_fail_mode(MockFailMode::TxAlwaysFails);

        let result = transport.transmit(b"test");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), LoRaError::TxFailed));
    }

    #[test]
    fn test_mock_channel_busy() {
        let mut transport = MockTransport::new();
        transport.connect().unwrap();

        assert!(!transport.channel_activity_detected().unwrap());

        transport.set_channel_busy(true);
        assert!(transport.channel_activity_detected().unwrap());
    }

    #[test]
    fn test_packet_too_large() {
        let mut transport = MockTransport::new();
        transport.connect().unwrap();

        let large_data = vec![0u8; LUNAR_PACKET_SIZE + 1];
        let result = transport.transmit(&large_data);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), LoRaError::PacketTooLarge));
    }
}
