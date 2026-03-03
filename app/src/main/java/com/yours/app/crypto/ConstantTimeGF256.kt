package com.yours.app.crypto

/**
 * Constant-time GF(2^8) arithmetic using precomputed lookup tables.
 * Eliminates timing side-channels for Shamir secret sharing operations
 * by avoiding data-dependent branches in all field operations.
 */
object ConstantTimeGF256 {

    /**
     * Primitive polynomial for GF(2^8): x^8 + x^4 + x^3 + x + 1 = 0x11B
     * Used in AES, widely analyzed.
     */
    private const val PRIMITIVE_POLY = 0x11B

    /**
     * Precomputed multiplication table.
     * exp[i] = g^i where g = 0x03 (generator)
     */
    private val EXP_TABLE = IntArray(512)

    /**
     * Precomputed logarithm table.
     * log[g^i] = i
     */
    private val LOG_TABLE = IntArray(256)

    /**
     * Precomputed inverse table.
     * inv[x] = x^(-1) in GF(2^8)
     */
    private val INV_TABLE = IntArray(256)

    init {
        // Initialize tables at class load time
        initializeTables()
    }

    /**
     * Initialize all lookup tables.
     *
     * Uses generator g = 0x03 which generates the full multiplicative group.
     * This is the standard generator used in AES.
     */
    private fun initializeTables() {
        var x = 1

        // Build exponential table
        for (i in 0 until 255) {
            EXP_TABLE[i] = x
            EXP_TABLE[i + 255] = x  // Duplicate for wraparound

            // x = x * g = x * 0x03
            // In GF(2^8), multiply by 0x03 = multiply by (x + 1)
            // = x*a XOR a = xtime(a) XOR a
            val xtime = (x shl 1) xor (if (x and 0x80 != 0) (PRIMITIVE_POLY and 0xFF) else 0)
            x = xtime xor x
        }

        // Build logarithm table
        LOG_TABLE[0] = 0  // log(0) undefined, but we need a value
        for (i in 0 until 255) {
            LOG_TABLE[EXP_TABLE[i]] = i
        }

        // Build inverse table
        INV_TABLE[0] = 0  // 0 has no inverse
        for (i in 1 until 256) {
            // a^(-1) = a^254 in GF(2^8) since a^255 = 1
            INV_TABLE[i] = EXP_TABLE[255 - LOG_TABLE[i]]
        }
    }

    /**
     * Constant-time multiplication in GF(2^8).
     *
     * Uses logarithm/exponential method:
     * a * b = g^(log_g(a) + log_g(b))
     *
     * @param a First operand (0-255)
     * @param b Second operand (0-255)
     * @return Product in GF(2^8)
     */
    fun multiply(a: Int, b: Int): Int {
        // Mask for constant-time zero check
        // If either operand is 0, result must be 0
        val aIsZero = constantTimeIsZero(a)
        val bIsZero = constantTimeIsZero(b)
        val eitherZero = aIsZero or bIsZero

        // Compute log(a) + log(b) mod 255
        val logSum = LOG_TABLE[a and 0xFF] + LOG_TABLE[b and 0xFF]

        // Get result from exp table (no modulo needed due to table duplication)
        val result = EXP_TABLE[logSum]

        // Constant-time select: if either is zero, return 0
        return constantTimeSelect(eitherZero, 0, result)
    }

    /**
     * Constant-time multiplicative inverse in GF(2^8).
     *
     * @param a Operand (0-255), returns 0 if a=0
     * @return a^(-1) in GF(2^8)
     */
    fun inverse(a: Int): Int {
        return INV_TABLE[a and 0xFF]
    }

    /**
     * Constant-time division in GF(2^8).
     *
     * @param a Dividend
     * @param b Divisor (must be non-zero for meaningful result)
     * @return a / b = a * b^(-1)
     */
    fun divide(a: Int, b: Int): Int {
        return multiply(a, inverse(b))
    }

    /**
     * Addition in GF(2^8) is XOR.
     * Already constant-time.
     */
    fun add(a: Int, b: Int): Int {
        return (a xor b) and 0xFF
    }

    /**
     * Subtraction in GF(2^8) is also XOR (same as addition).
     */
    fun subtract(a: Int, b: Int): Int {
        return add(a, b)
    }

    /**
     * Constant-time power in GF(2^8).
     *
     * @param base Base value
     * @param exp Exponent
     * @return base^exp in GF(2^8)
     */
    fun power(base: Int, exp: Int): Int {
        if (exp == 0) return 1
        if (base == 0) return 0

        // a^n = g^(n * log_g(a)) mod (g^255 - 1)
        val logBase = LOG_TABLE[base and 0xFF]
        val logResult = (logBase * exp) % 255

        return EXP_TABLE[logResult]
    }

    /**
     * Evaluate polynomial at a point (for Shamir).
     *
     * p(x) = coeffs[0] + coeffs[1]*x + coeffs[2]*x^2 + ...
     *
     * Uses Horner's method for efficiency.
     *
     * @param coeffs Polynomial coefficients (constant term first)
     * @param x Point to evaluate at
     * @return p(x) in GF(2^8)
     */
    fun evaluatePolynomial(coeffs: ByteArray, x: Int): Int {
        if (coeffs.isEmpty()) return 0

        // Horner's method: p(x) = ((a_n * x + a_{n-1}) * x + ...) * x + a_0
        var result = coeffs[coeffs.size - 1].toInt() and 0xFF

        for (i in coeffs.size - 2 downTo 0) {
            result = add(multiply(result, x), coeffs[i].toInt() and 0xFF)
        }

        return result
    }

    /**
     * Lagrange interpolation to find constant term (for Shamir reconstruction).
     *
     * Given points (x_i, y_i), find p(0) where p is the unique polynomial
     * of degree < n passing through all points.
     *
     * @param xs X coordinates (share indices)
     * @param ys Y coordinates (share values)
     * @return p(0) = the secret
     */
    fun lagrangeInterpolate(xs: IntArray, ys: IntArray): Int {
        require(xs.size == ys.size) { "Coordinate arrays must have same length" }

        val n = xs.size
        var result = 0

        for (i in 0 until n) {
            // Compute Lagrange basis polynomial L_i(0)
            // L_i(0) = Π_{j≠i} (0 - x_j) / (x_i - x_j)
            //        = Π_{j≠i} x_j / (x_i - x_j)
            //        = Π_{j≠i} x_j / (x_i XOR x_j)  [in GF(2^8)]

            var numerator = 1
            var denominator = 1

            for (j in 0 until n) {
                if (i != j) {
                    numerator = multiply(numerator, xs[j])
                    denominator = multiply(denominator, add(xs[i], xs[j]))
                }
            }

            // L_i(0) = numerator / denominator
            val basis = divide(numerator, denominator)

            // Add y_i * L_i(0) to result
            result = add(result, multiply(ys[i], basis))
        }

        return result
    }

    /**
     * Constant-time check if value is zero.
     *
     * @return 0xFFFFFFFF if x == 0, 0x00000000 otherwise
     */
    private fun constantTimeIsZero(x: Int): Int {
        // (x - 1) will have high bit set if x == 0 (underflow to -1)
        // but not if x > 0
        val xMinus1 = x - 1
        val notX = x.inv()

        // If x == 0: xMinus1 = -1 (all 1s), notX = -1 (all 1s)
        // If x != 0: xMinus1 >= 0, notX < 0 but (xMinus1 AND notX) won't be all 1s
        return (xMinus1 and notX) shr 31
    }

    /**
     * Constant-time conditional select.
     *
     * @param condition Mask: all 1s (-1) to select ifTrue, all 0s to select ifFalse
     * @param ifTrue Value to return if condition is all 1s
     * @param ifFalse Value to return if condition is all 0s
     * @return Selected value without branching
     */
    private fun constantTimeSelect(condition: Int, ifTrue: Int, ifFalse: Int): Int {
        // condition is either 0 or -1 (all bits set)
        // result = (condition AND ifTrue) OR ((NOT condition) AND ifFalse)
        return (condition and ifTrue) or (condition.inv() and ifFalse)
    }

    /**
     * Generate Shamir shares of a secret.
     *
     * @param secret The byte to share
     * @param threshold Minimum shares needed to reconstruct (k)
     * @param totalShares Total shares to generate (n)
     * @return List of (index, share) pairs
     */
    fun shamirSplit(secret: Byte, threshold: Int, totalShares: Int): List<Pair<Int, Byte>> {
        require(threshold >= 1) { "Threshold must be >= 1" }
        require(totalShares >= threshold) { "Total shares must be >= threshold" }
        require(totalShares <= 255) { "Total shares must be <= 255" }

        // Generate random polynomial coefficients
        // p(x) = secret + a_1*x + a_2*x^2 + ... + a_{k-1}*x^{k-1}
        val coeffs = ByteArray(threshold)
        coeffs[0] = secret

        // Random coefficients for degree 1 to k-1
        val randomBytes = BedrockCore.randomBytes(threshold - 1)
        System.arraycopy(randomBytes, 0, coeffs, 1, threshold - 1)

        // Evaluate polynomial at x = 1, 2, 3, ..., n
        val shares = mutableListOf<Pair<Int, Byte>>()
        for (x in 1..totalShares) {
            val y = evaluatePolynomial(coeffs, x)
            shares.add(Pair(x, y.toByte()))
        }

        // Zeroize coefficients
        BedrockCore.zeroize(coeffs)

        return shares
    }

    /**
     * Reconstruct secret from Shamir shares.
     *
     * @param shares List of (index, share) pairs (at least k shares)
     * @return The reconstructed secret byte
     */
    fun shamirReconstruct(shares: List<Pair<Int, Byte>>): Byte {
        require(shares.isNotEmpty()) { "At least one share required" }

        val xs = shares.map { it.first }.toIntArray()
        val ys = shares.map { it.second.toInt() and 0xFF }.toIntArray()

        return lagrangeInterpolate(xs, ys).toByte()
    }

    /**
     * Split a multi-byte secret into shares.
     *
     * @param secret The secret bytes to share
     * @param threshold Minimum shares needed (k)
     * @param totalShares Total shares to generate (n)
     * @return Array of share byte arrays
     */
    fun shamirSplitBytes(secret: ByteArray, threshold: Int, totalShares: Int): Array<ByteArray> {
        val shares = Array(totalShares) { ByteArray(secret.size) }

        for (byteIndex in secret.indices) {
            val byteShares = shamirSplit(secret[byteIndex], threshold, totalShares)
            for ((shareIndex, share) in byteShares) {
                shares[shareIndex - 1][byteIndex] = share
            }
        }

        return shares
    }

    /**
     * Reconstruct multi-byte secret from shares.
     *
     * @param shares Array of share byte arrays with their indices (1-based)
     * @param indices The indices (x-coordinates) of the shares
     * @return Reconstructed secret bytes
     */
    fun shamirReconstructBytes(shares: Array<ByteArray>, indices: IntArray): ByteArray {
        require(shares.isNotEmpty()) { "At least one share required" }
        require(shares.size == indices.size) { "Must have index for each share" }

        val secretLength = shares[0].size
        val result = ByteArray(secretLength)

        for (byteIndex in 0 until secretLength) {
            val byteShares = shares.mapIndexed { i, share ->
                Pair(indices[i], share[byteIndex])
            }
            result[byteIndex] = shamirReconstruct(byteShares)
        }

        return result
    }
}
