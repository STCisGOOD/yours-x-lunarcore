package com.yours.app.mesh

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.ParcelUuid
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlin.coroutines.resume

/**
 * BLE Scanner for discovering MeshCore devices.
 *
 * Scans for devices advertising the Nordic UART Service (NUS) which is used
 * by MeshCore firmware for BLE communication.
 *
 * ## Required Permissions
 *
 * Android 12+ (API 31+):
 * - BLUETOOTH_SCAN
 * - BLUETOOTH_CONNECT
 *
 * Android 11 and below:
 * - BLUETOOTH
 * - BLUETOOTH_ADMIN
 * - ACCESS_FINE_LOCATION
 *
 * ## Usage
 *
 * ```kotlin
 * val scanner = MeshCoreBleScanner(context)
 *
 * // Scan for devices
 * val devices = scanner.scanForDevices(timeoutMs = 10000)
 *
 * // Filter for MeshCore devices
 * val meshCoreDevices = devices.filter { it.hasMeshCoreService }
 *
 * // Connect to first device
 * if (meshCoreDevices.isNotEmpty()) {
 *     val address = meshCoreDevices.first().address
 *     meshCoreManager.connect(MeshConnection.Ble(address))
 * }
 *
 * // Stop scanning
 * scanner.stopScan()
 * ```
 */
@SuppressLint("MissingPermission")
class MeshCoreBleScanner(private val context: Context) {

    companion object {
        private const val TAG = "MeshCoreBleScanner"

        // Nordic UART Service UUID - used by MeshCore devices
        val NUS_SERVICE_UUID: UUID = UUID.fromString("6E400001-B5A3-F393-E0A9-E50E24DCCA9E")

        // Alternative MeshCore-specific service UUID (for custom firmware)
        val MESHCORE_SERVICE_UUID: UUID = UUID.fromString("6E400001-B5A3-F393-E0A9-E50E24DCCA9E")

        // Device name patterns that indicate MeshCore devices
        private val MESHCORE_NAME_PATTERNS = listOf(
            "meshcore",
            "heltec",
            "lilygo",
            "t-beam",
            "lora",
            "rak",
            "wisblock",
            "sx126"
        )

        // Default scan settings
        private const val DEFAULT_SCAN_TIMEOUT_MS = 10000L
        private const val MIN_RSSI = -100  // Filter out very weak signals
    }

    private var bluetoothAdapter: BluetoothAdapter? = null
    private var bleScanner: BluetoothLeScanner? = null
    private var isScanning = false

    // Discovered devices
    private val discoveredDevices = ConcurrentHashMap<String, BleDeviceInfo>()

    // Scan callback
    private var scanCallback: ScanCallback? = null

    /**
     * Initialize the Bluetooth adapter.
     */
    private fun initialize(): Boolean {
        if (bluetoothAdapter != null) return true

        val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        bluetoothAdapter = bluetoothManager?.adapter

        if (bluetoothAdapter == null || !bluetoothAdapter!!.isEnabled) {
            return false
        }

        bleScanner = bluetoothAdapter?.bluetoothLeScanner
        return bleScanner != null
    }

    /**
     * Scan for BLE MeshCore devices.
     *
     * @param timeoutMs How long to scan (default 10 seconds)
     * @param filterMeshCoreOnly If true, only return devices that appear to be MeshCore
     * @return List of discovered devices
     */
    suspend fun scanForDevices(
        timeoutMs: Long = DEFAULT_SCAN_TIMEOUT_MS,
        filterMeshCoreOnly: Boolean = false
    ): List<BleDeviceInfo> = withContext(Dispatchers.IO) {
        if (!initialize()) {
            return@withContext emptyList()
        }

        discoveredDevices.clear()

        val scanComplete = CompletableDeferred<List<BleDeviceInfo>>()

        // Create scan callback
        scanCallback = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                processScanResult(result)
            }

            override fun onBatchScanResults(results: List<ScanResult>) {
                results.forEach { processScanResult(it) }
            }

            override fun onScanFailed(errorCode: Int) {
                android.util.Log.e(TAG, "Scan failed with error: $errorCode")
                if (!scanComplete.isCompleted) {
                    scanComplete.complete(discoveredDevices.values.toList())
                }
            }
        }

        // Build scan filters
        val filters = buildScanFilters()

        // Build scan settings
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .setReportDelay(0)
            .build()

        try {
            // Start scanning
            isScanning = true
            bleScanner?.startScan(filters, settings, scanCallback)

            // Wait for timeout
            delay(timeoutMs)

            // Stop scanning
            stopScan()

            // Return results
            val allDevices = discoveredDevices.values.toList()

            if (filterMeshCoreOnly) {
                allDevices.filter { it.hasMeshCoreService || isMeshCoreName(it.name) }
            } else {
                allDevices
            }

        } catch (e: Exception) {
            android.util.Log.e(TAG, "Scan error", e)
            stopScan()
            emptyList()
        }
    }

    /**
     * Scan for a specific device by MAC address.
     *
     * @param macAddress Target device MAC address
     * @param timeoutMs Scan timeout
     * @return Device info if found, null otherwise
     */
    suspend fun scanForDevice(
        macAddress: String,
        timeoutMs: Long = DEFAULT_SCAN_TIMEOUT_MS
    ): BleDeviceInfo? = withContext(Dispatchers.IO) {
        if (!initialize()) {
            return@withContext null
        }

        val targetMac = macAddress.uppercase()
        var foundDevice: BleDeviceInfo? = null

        val scanComplete = CompletableDeferred<BleDeviceInfo?>()

        scanCallback = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                if (result.device.address.uppercase() == targetMac) {
                    foundDevice = createDeviceInfo(result)
                    stopScan()
                    if (!scanComplete.isCompleted) {
                        scanComplete.complete(foundDevice)
                    }
                }
            }

            override fun onScanFailed(errorCode: Int) {
                if (!scanComplete.isCompleted) {
                    scanComplete.complete(null)
                }
            }
        }

        // Build filter for specific address
        val filter = ScanFilter.Builder()
            .setDeviceAddress(targetMac)
            .build()

        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()

        try {
            isScanning = true
            bleScanner?.startScan(listOf(filter), settings, scanCallback)

            // Wait for device or timeout
            withTimeoutOrNull(timeoutMs) {
                scanComplete.await()
            } ?: run {
                stopScan()
                null
            }

        } catch (e: Exception) {
            stopScan()
            null
        }
    }

    /**
     * Start continuous scanning and invoke callback for each device found.
     *
     * @param onDeviceFound Callback invoked for each discovered device
     */
    fun startContinuousScan(onDeviceFound: (BleDeviceInfo) -> Unit) {
        if (!initialize()) {
            return
        }

        if (isScanning) {
            stopScan()
        }

        discoveredDevices.clear()

        scanCallback = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                val deviceInfo = processScanResult(result)
                if (deviceInfo != null) {
                    onDeviceFound(deviceInfo)
                }
            }

            override fun onBatchScanResults(results: List<ScanResult>) {
                results.forEach { result ->
                    val deviceInfo = processScanResult(result)
                    if (deviceInfo != null) {
                        onDeviceFound(deviceInfo)
                    }
                }
            }

            override fun onScanFailed(errorCode: Int) {
                android.util.Log.e(TAG, "Continuous scan failed: $errorCode")
            }
        }

        val filters = buildScanFilters()
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_BALANCED)
            .setReportDelay(500) // Batch results every 500ms
            .build()

        isScanning = true
        bleScanner?.startScan(filters, settings, scanCallback)
    }

    /**
     * Stop any ongoing scan.
     */
    fun stopScan() {
        if (isScanning) {
            try {
                scanCallback?.let { callback ->
                    bleScanner?.stopScan(callback)
                }
            } catch (e: Exception) {
                // Ignore stop errors
            }
            isScanning = false
            scanCallback = null
        }
    }

    /**
     * Process a scan result and add to discovered devices.
     */
    private fun processScanResult(result: ScanResult): BleDeviceInfo? {
        val device = result.device
        val rssi = result.rssi

        // Filter weak signals
        if (rssi < MIN_RSSI) {
            return null
        }

        val deviceInfo = createDeviceInfo(result)

        // Check if this is a new device or better RSSI
        val existing = discoveredDevices[device.address]
        if (existing == null || deviceInfo.rssi > existing.rssi) {
            discoveredDevices[device.address] = deviceInfo
            return deviceInfo
        }

        return null
    }

    /**
     * Create BleDeviceInfo from a scan result.
     */
    private fun createDeviceInfo(result: ScanResult): BleDeviceInfo {
        val device = result.device
        val scanRecord = result.scanRecord

        // Check for NUS service UUID in advertised services
        val serviceUuids = scanRecord?.serviceUuids ?: emptyList()
        val hasMeshCore = serviceUuids.any { parcelUuid ->
            parcelUuid.uuid == NUS_SERVICE_UUID || parcelUuid.uuid == MESHCORE_SERVICE_UUID
        } || isMeshCoreName(device.name)

        return BleDeviceInfo(
            name = device.name,
            address = device.address,
            rssi = result.rssi,
            hasMeshCoreService = hasMeshCore
        )
    }

    /**
     * Build scan filters for MeshCore devices.
     */
    private fun buildScanFilters(): List<ScanFilter> {
        return listOf(
            // Filter for NUS service
            ScanFilter.Builder()
                .setServiceUuid(ParcelUuid(NUS_SERVICE_UUID))
                .build()
        )
    }

    /**
     * Check if a device name indicates a MeshCore device.
     */
    private fun isMeshCoreName(name: String?): Boolean {
        if (name.isNullOrBlank()) return false
        val lowerName = name.lowercase()
        return MESHCORE_NAME_PATTERNS.any { pattern ->
            lowerName.contains(pattern)
        }
    }

    /**
     * Check if Bluetooth is enabled.
     */
    fun isBluetoothEnabled(): Boolean {
        if (!initialize()) return false
        return bluetoothAdapter?.isEnabled == true
    }

    /**
     * Get currently discovered devices without starting a new scan.
     */
    fun getDiscoveredDevices(): List<BleDeviceInfo> {
        return discoveredDevices.values.toList()
    }

    /**
     * Clear discovered devices list.
     */
    fun clearDiscoveredDevices() {
        discoveredDevices.clear()
    }

    /**
     * Check if currently scanning.
     */
    fun isCurrentlyScanning(): Boolean = isScanning
}
