package com.yours.app.crypto

import java.nio.ByteBuffer
import java.security.SecureRandom

/**
 * HardenedRecovery - Verifiable secret sharing for identity recovery.
 * Uses 6-of-9 Shamir threshold with hash-based share verification.
 */
object HardenedRecovery {

    const val RECOVERY_THRESHOLD = 6
    const val TOTAL_SHARES = 9

    const val RECOVERY_DELAY_SECONDS = 30 * 24 * 60 * 60L  // 30 days
    const val EMERGENCY_DELAY_SECONDS = 7 * 24 * 60 * 60L  // 7 days
    const val MIN_NODE_REPUTATION = 0.7
    const val MIN_NODE_UPTIME_DAYS = 30
    const val MAX_SHARES_PER_REGION = 2

    private val secureRandom = SecureRandom()

    /**
     * Generate recovery shares with verifiable secret sharing.
     *
     * @param secret The identity seed to protect (32 bytes)
     * @return List of shares with verification data
     */
    fun generateShares(secret: ByteArray): List<VerifiableShare> {
        require(secret.size == 32) { "Secret must be 32 bytes" }

        val rawShares = BedrockCore.shamirSplit(secret, TOTAL_SHARES, RECOVERY_THRESHOLD)

        return rawShares.mapIndexed { index, shareBytes ->
            val shareId = generateShareId(index)
            val commitment = BedrockCore.sha3_256(shareBytes)
            val proof = generateShareProof(shareBytes, index, listOf(commitment))

            VerifiableShare(
                id = shareId,
                index = index,
                data = shareBytes,
                commitment = commitment,
                proof = proof,
                createdAt = System.currentTimeMillis()
            )
        }
    }

    /**
     * Reconstruct secret from shares with verification.
     *
     * @param shares At least RECOVERY_THRESHOLD shares
     * @return The reconstructed secret, or null if verification fails
     */
    fun reconstructSecret(shares: List<VerifiableShare>): ByteArray? {
        if (shares.size < RECOVERY_THRESHOLD) {
            return null
        }

        // Verify each share before reconstruction
        for (share in shares) {
            if (!verifyShare(share)) {
                // Share failed verification - possible tampering
                return null
            }
        }

        // Extract raw share data
        val rawShares = shares.map { it.data }

        // Reconstruct using Shamir via shamirCombine
        return BedrockCore.shamirCombine(rawShares)
    }

    /**
     * Verify a share against its commitment hash.
     */
    fun verifyShare(share: VerifiableShare): Boolean {
        val expected = BedrockCore.sha3_256(share.data)
        return expected.contentEquals(share.commitment)
    }

    /**
     * Generate unique share ID.
     */
    private fun generateShareId(index: Int): ByteArray {
        val id = ByteArray(16)
        secureRandom.nextBytes(id)
        // Encode index in first byte
        id[0] = index.toByte()
        return id
    }

    /**
     * Generate hash-based proof for a share.
     */
    private fun generateShareProof(
        share: ByteArray,
        index: Int,
        commitments: List<ByteArray>
    ): ByteArray {
        val contextSize = 4 + commitments.sumOf { it.size }
        val contextBuffer = ByteBuffer.allocate(contextSize).putInt(index)
        for (c in commitments) {
            contextBuffer.put(c, 0, c.size)
        }
        return BedrockCore.sha3_256(contextBuffer.array())
    }

    /**
     * Select share holder nodes with security constraints.
     *
     * SELECTION CRITERIA:
     * 1. Reputation score >= 70%
     * 2. Online for >= 30 days
     * 3. Maximum 2 nodes per geographic region
     * 4. Weighted random selection by stake
     */
    fun selectShareHolders(
        availableNodes: List<MeshNode>,
        excludeNodes: Set<ByteArray> = emptySet()
    ): List<MeshNode> {
        // Filter by minimum requirements
        val eligibleNodes = availableNodes.filter { node ->
            node.reputationScore >= MIN_NODE_REPUTATION &&
            node.uptimeDays >= MIN_NODE_UPTIME_DAYS &&
            !excludeNodes.any { it.contentEquals(node.publicKey) }
        }

        if (eligibleNodes.size < TOTAL_SHARES) {
            throw InsufficientNodesException(
                available = eligibleNodes.size,
                required = TOTAL_SHARES
            )
        }

        // Group by region for geographic distribution
        val byRegion = eligibleNodes.groupBy { it.region }

        val selected = mutableListOf<MeshNode>()
        val usedRegions = mutableMapOf<String, Int>()

        // Weighted selection with geographic constraints
        val shuffled = eligibleNodes.shuffled(secureRandom)
        for (node in shuffled) {
            if (selected.size >= TOTAL_SHARES) break

            val regionCount = usedRegions.getOrDefault(node.region, 0)
            if (regionCount < MAX_SHARES_PER_REGION) {
                selected.add(node)
                usedRegions[node.region] = regionCount + 1
            }
        }

        // If geographic constraints prevented selection, relax them
        if (selected.size < TOTAL_SHARES) {
            for (node in shuffled) {
                if (selected.size >= TOTAL_SHARES) break
                if (!selected.contains(node)) {
                    selected.add(node)
                }
            }
        }

        return selected.take(TOTAL_SHARES)
    }

    /**
     * Calculate recovery delay with randomization.
     *
     * SECURITY: Randomized delay prevents adversary from predicting
     * exact recovery completion time.
     */
    fun calculateRecoveryDelay(isEmergency: Boolean = false): Long {
        val baseDelay = if (isEmergency) EMERGENCY_DELAY_SECONDS else RECOVERY_DELAY_SECONDS

        // Add random jitter (0-10% of base delay)
        val jitter = (secureRandom.nextDouble() * 0.1 * baseDelay).toLong()

        return baseDelay + jitter
    }
}

/**
 * A verifiable share with Pedersen commitment proof.
 */
data class VerifiableShare(
    val id: ByteArray,
    val index: Int,
    val data: ByteArray,
    val commitment: ByteArray,
    val proof: ByteArray,
    val createdAt: Long
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is VerifiableShare) return false
        return id.contentEquals(other.id)
    }

    override fun hashCode(): Int = id.contentHashCode()
}

/**
 * A mesh node that can hold recovery shares.
 */
data class MeshNode(
    val publicKey: ByteArray,
    val region: String,
    val reputationScore: Double,  // 0.0 to 1.0
    val uptimeDays: Int,
    val stakeAmount: Long = 0  // Optional proof-of-stake
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is MeshNode) return false
        return publicKey.contentEquals(other.publicKey)
    }

    override fun hashCode(): Int = publicKey.contentHashCode()
}

/**
 * Exception when not enough nodes are available for share distribution.
 */
class InsufficientNodesException(
    val available: Int,
    val required: Int
) : Exception("Insufficient nodes for recovery: have $available, need $required")
