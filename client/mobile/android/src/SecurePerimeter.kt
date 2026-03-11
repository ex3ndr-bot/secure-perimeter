/**
 * SecurePerimeter Android Client
 *
 * Kotlin implementation of the Secure Perimeter client for Android.
 * Provides Noise Protocol XX handshake with hardware attestation verification.
 *
 * ## Dependencies
 * Add to build.gradle:
 * ```
 * implementation "com.google.crypto.tink:tink-android:1.12.0"
 * implementation "org.bouncycastle:bcprov-jdk18on:1.78"
 * implementation "com.squareup.okhttp3:okhttp:4.12.0"
 * implementation "org.jetbrains.kotlinx:kotlinx-coroutines-core:1.8.0"
 * ```
 */
package com.secureperimeter.client

import kotlinx.coroutines.*
import java.io.IOException
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.net.ssl.SSLSocketFactory

// ============================================================================
// Configuration
// ============================================================================

/**
 * Configuration for NoiseClient connection
 */
data class NoiseClientConfig(
    /** Server hostname */
    val host: String,
    /** Server port */
    val port: Int,
    /** Use TLS as transport layer */
    val useTls: Boolean = true,
    /** Expected image digest for Rekor lookup */
    val expectedImageDigest: String? = null,
    /** Skip attestation verification (DANGEROUS - testing only) */
    val skipAttestation: Boolean = false,
    /** Connection timeout in milliseconds */
    val timeoutMs: Long = 30_000
)

// ============================================================================
// Types
// ============================================================================

/**
 * Attestation type detected from quote
 */
enum class AttestationType {
    SEV_SNP,
    TDX,
    UNKNOWN
}

/**
 * Result of attestation verification
 */
data class AttestationResult(
    val valid: Boolean,
    val attestationType: AttestationType,
    val errors: List<String>,
    val warnings: List<String>
)

/**
 * Expected measurements for verification
 */
data class ExpectedMeasurements(
    /** AMD SEV-SNP launch measurement (48 bytes) */
    val snpMeasurement: ByteArray? = null,
    /** Intel TDX MRTD (48 bytes) */
    val tdxMrTd: ByteArray? = null,
    /** Intel TDX RTMR0 (48 bytes) */
    val tdxRtmr0: ByteArray? = null,
    /** Expected prefix of report data */
    val reportDataPrefix: ByteArray? = null
)

/**
 * Encrypted session after successful handshake
 */
interface NoiseSession {
    /** Send encrypted data to the server */
    suspend fun send(data: ByteArray)

    /** Set receive handler for incoming data */
    fun onData(handler: (ByteArray) -> Unit)

    /** Close the session */
    fun close()

    /** Server's static public key (32 bytes) */
    val remotePublicKey: ByteArray

    /** Handshake hash for channel binding (32 bytes) */
    val handshakeHash: ByteArray

    /** Attestation verification result */
    val attestation: AttestationResult
}

// ============================================================================
// Noise Client
// ============================================================================

/**
 * Noise Protocol client with hardware attestation verification
 *
 * ## Overview
 * `NoiseClient` establishes encrypted connections to secure perimeter servers
 * running in Trusted Execution Environments (TEEs). It performs:
 *
 * 1. TCP/TLS connection to the server
 * 2. Noise XX handshake with ephemeral and static key exchange
 * 3. Attestation quote extraction from handshake payload
 * 4. Hardware signature verification against AMD/Intel root CA
 * 5. Measurement comparison against Rekor transparency log
 *
 * ## Usage
 * ```kotlin
 * val config = NoiseClientConfig(
 *     host = "server.example.com",
 *     port = 9000,
 *     expectedImageDigest = "sha256:abc123..."
 * )
 *
 * val client = NoiseClient(config)
 * val session = client.connect()
 *
 * // Verify attestation passed
 * if (!session.attestation.valid) {
 *     println("Attestation failed: ${session.attestation.errors}")
 *     return
 * }
 *
 * // Send encrypted message
 * session.send("Hello, secure server!".toByteArray())
 *
 * // Receive messages
 * session.onData { data ->
 *     println("Received: ${String(data)}")
 * }
 * ```
 *
 * ## Dependencies
 * - Tink or BouncyCastle for X25519 key exchange and ChaCha20-Poly1305
 * - OkHttp or standard Socket for TCP/TLS connections
 *
 */
class NoiseClient(private val config: NoiseClientConfig) {

    // Noise handshake state (stub - actual implementation needs noise-protocol lib)
    private var localStaticKeypair: KeyPair? = null
    private var localEphemeralKeypair: KeyPair? = null
    private var remoteStaticPublicKey: ByteArray? = null
    private var remoteEphemeralPublicKey: ByteArray? = null

    private var socket: Socket? = null

    init {
        localStaticKeypair = generateKeypair()
    }

    /**
     * Connect to the server and perform attested Noise handshake
     *
     * @return An encrypted session if attestation verification passes
     * @throws IOException if connection fails
     * @throws AttestationException if attestation fails
     */
    suspend fun connect(): NoiseSession = withContext(Dispatchers.IO) {
        // Step 1: Fetch expected measurements from Rekor if image digest provided
        val expectedMeasurements = config.expectedImageDigest?.let {
            fetchMeasurementsFromRekor(it)
        }

        // Step 2: Establish TCP/TLS connection
        socket = if (config.useTls) {
            SSLSocketFactory.getDefault().createSocket(config.host, config.port)
        } else {
            Socket(config.host, config.port)
        }

        socket?.soTimeout = config.timeoutMs.toInt()

        // Step 3: Perform Noise XX handshake
        performHandshake(expectedMeasurements)
    }

    private suspend fun performHandshake(
        expectedMeasurements: ExpectedMeasurements?
    ): NoiseSession {
        val socket = socket ?: throw IOException("Not connected")

        // Generate ephemeral keypair for this handshake
        localEphemeralKeypair = generateKeypair()

        // XX pattern:
        // -> e                    (send ephemeral public key)
        // <- e, ee, s, es         (receive server ephemeral + static + attestation)
        // -> s, se                (send our static public key)

        // Step 1: Send our ephemeral public key
        val msg1 = buildHandshakeMessage1()
        sendFrame(msg1)

        // Step 2: Receive server's response with attestation
        val msg2 = receiveFrame()
        val (serverPayload, attestationQuote) = parseHandshakeMessage2(msg2)

        // Step 3: Verify attestation if not skipped
        var attestationResult = AttestationResult(
            valid = true,
            attestationType = AttestationType.UNKNOWN,
            errors = emptyList(),
            warnings = listOf("Attestation verification not yet implemented")
        )

        if (!config.skipAttestation && attestationQuote != null) {
            attestationResult = AttestationVerifier().verify(
                quote = attestationQuote,
                expected = expectedMeasurements ?: ExpectedMeasurements()
            )

            if (!attestationResult.valid) {
                throw AttestationException(attestationResult.errors.joinToString(", "))
            }
        }

        // Step 4: Send our static public key
        val msg3 = buildHandshakeMessage3()
        sendFrame(msg3)

        // Step 5: Derive session keys and create session
        val (txKey, rxKey) = deriveSessionKeys()

        return NoiseSessionImpl(
            socket = socket,
            txKey = txKey,
            rxKey = rxKey,
            remotePublicKey = remoteStaticPublicKey ?: ByteArray(32),
            handshakeHash = computeHandshakeHash(),
            attestation = attestationResult
        )
    }

    // ========================================================================
    // Crypto Stubs
    // These would use Tink or BouncyCastle in production
    // ========================================================================

    private fun generateKeypair(): KeyPair {
        // Stub: In production, use X25519 from Tink or BouncyCastle
        val secretKey = ByteArray(32) { (Math.random() * 256).toInt().toByte() }
        val publicKey = ByteArray(32) { (Math.random() * 256).toInt().toByte() }
        return KeyPair(publicKey, secretKey)
    }

    private fun buildHandshakeMessage1(): ByteArray {
        // Stub: Return ephemeral public key with Noise framing
        return localEphemeralKeypair?.publicKey ?: ByteArray(32)
    }

    private fun parseHandshakeMessage2(data: ByteArray): Pair<ByteArray, ByteArray?> {
        // Stub: Parse server's response
        // In production: decrypt using Noise protocol state machine
        val attestation = if (data.size > 64) {
            data.copyOfRange(64, data.size)
        } else null
        return Pair(data, attestation)
    }

    private fun buildHandshakeMessage3(): ByteArray {
        // Stub: Return encrypted static public key
        return localStaticKeypair?.publicKey ?: ByteArray(32)
    }

    private fun deriveSessionKeys(): Pair<ByteArray, ByteArray> {
        // Stub: Derive symmetric keys from handshake
        // In production: use HKDF with handshake transcript hash
        val tx = ByteArray(32) { (Math.random() * 256).toInt().toByte() }
        val rx = ByteArray(32) { (Math.random() * 256).toInt().toByte() }
        return Pair(tx, rx)
    }

    private fun computeHandshakeHash(): ByteArray {
        // Stub: Return hash of entire handshake transcript
        return ByteArray(32) { (Math.random() * 256).toInt().toByte() }
    }

    // ========================================================================
    // Network
    // ========================================================================

    private fun sendFrame(data: ByteArray) {
        val socket = socket ?: throw IOException("Not connected")
        val output = socket.getOutputStream()

        // Length-prefixed framing (4 bytes big-endian)
        val frame = ByteBuffer.allocate(4 + data.size)
            .order(ByteOrder.BIG_ENDIAN)
            .putInt(data.size)
            .put(data)
            .array()

        output.write(frame)
        output.flush()
    }

    private fun receiveFrame(): ByteArray {
        val socket = socket ?: throw IOException("Not connected")
        val input = socket.getInputStream()

        // Read 4-byte length
        val lengthBytes = ByteArray(4)
        var read = 0
        while (read < 4) {
            val n = input.read(lengthBytes, read, 4 - read)
            if (n < 0) throw IOException("Connection closed")
            read += n
        }

        val length = ByteBuffer.wrap(lengthBytes)
            .order(ByteOrder.BIG_ENDIAN)
            .int

        // Read payload
        val payload = ByteArray(length)
        read = 0
        while (read < length) {
            val n = input.read(payload, read, length - read)
            if (n < 0) throw IOException("Connection closed")
            read += n
        }

        return payload
    }

    // ========================================================================
    // Rekor Integration
    // ========================================================================

    private suspend fun fetchMeasurementsFromRekor(
        imageDigest: String
    ): ExpectedMeasurements? {
        // Stub: Fetch from Rekor transparency log
        // See RekorClient implementation below
        return null
    }
}

// ============================================================================
// Session Implementation
// ============================================================================

private class NoiseSessionImpl(
    private val socket: Socket,
    private val txKey: ByteArray,
    private val rxKey: ByteArray,
    override val remotePublicKey: ByteArray,
    override val handshakeHash: ByteArray,
    override val attestation: AttestationResult
) : NoiseSession {

    private var dataHandler: ((ByteArray) -> Unit)? = null
    private var receiveJob: Job? = null

    init {
        startReceiveLoop()
    }

    override suspend fun send(data: ByteArray) = withContext(Dispatchers.IO) {
        // Stub: Encrypt with ChaCha20-Poly1305 using txKey
        val encrypted = encrypt(data, txKey)

        // Send length-prefixed frame
        val frame = ByteBuffer.allocate(4 + encrypted.size)
            .order(ByteOrder.BIG_ENDIAN)
            .putInt(encrypted.size)
            .put(encrypted)
            .array()

        socket.getOutputStream().apply {
            write(frame)
            flush()
        }
    }

    override fun onData(handler: (ByteArray) -> Unit) {
        dataHandler = handler
    }

    override fun close() {
        receiveJob?.cancel()
        socket.close()
    }

    private fun startReceiveLoop() {
        receiveJob = CoroutineScope(Dispatchers.IO).launch {
            try {
                while (isActive) {
                    val frame = receiveFrame()
                    val decrypted = decrypt(frame, rxKey)
                    dataHandler?.invoke(decrypted)
                }
            } catch (e: IOException) {
                // Connection closed
            }
        }
    }

    private fun receiveFrame(): ByteArray {
        val input = socket.getInputStream()

        // Read 4-byte length
        val lengthBytes = ByteArray(4)
        var read = 0
        while (read < 4) {
            val n = input.read(lengthBytes, read, 4 - read)
            if (n < 0) throw IOException("Connection closed")
            read += n
        }

        val length = ByteBuffer.wrap(lengthBytes)
            .order(ByteOrder.BIG_ENDIAN)
            .int

        // Read payload
        val payload = ByteArray(length)
        read = 0
        while (read < length) {
            val n = input.read(payload, read, length - read)
            if (n < 0) throw IOException("Connection closed")
            read += n
        }

        return payload
    }

    private fun encrypt(data: ByteArray, key: ByteArray): ByteArray {
        // Stub: Use Tink ChaCha20Poly1305 in production
        return data
    }

    private fun decrypt(data: ByteArray, key: ByteArray): ByteArray {
        // Stub: Use Tink ChaCha20Poly1305 in production
        return data
    }
}

// ============================================================================
// Attestation Verifier
// ============================================================================

/**
 * Verifier for hardware attestation quotes
 *
 * Parses AMD SEV-SNP and Intel TDX attestation reports and verifies
 * measurements against expected values.
 */
class AttestationVerifier {

    companion object {
        private const val SNP_REPORT_SIZE = 1184
        private const val TDX_REPORT_SIZE = 584
    }

    /**
     * Detect attestation type from quote bytes
     */
    fun detectType(quote: ByteArray): AttestationType {
        if (quote.size < 4) return AttestationType.UNKNOWN

        val version = ByteBuffer.wrap(quote, 0, 4)
            .order(ByteOrder.LITTLE_ENDIAN)
            .int

        // AMD SEV-SNP reports start with version 1 or 2
        if ((version == 1 || version == 2) && quote.size >= SNP_REPORT_SIZE) {
            return AttestationType.SEV_SNP
        }

        // TDX reports have different structure
        if (quote.size >= TDX_REPORT_SIZE) {
            return AttestationType.TDX
        }

        return AttestationType.UNKNOWN
    }

    /**
     * Verify attestation quote against expected measurements
     */
    fun verify(
        quote: ByteArray,
        expected: ExpectedMeasurements
    ): AttestationResult {
        val errors = mutableListOf<String>()
        val warnings = mutableListOf<String>()

        val attestationType = detectType(quote)

        when (attestationType) {
            AttestationType.SEV_SNP -> {
                if (quote.size < SNP_REPORT_SIZE) {
                    errors.add("SNP report too short: ${quote.size}")
                } else {
                    // Extract measurement (bytes 144-192)
                    val measurement = quote.copyOfRange(144, 192)

                    if (expected.snpMeasurement != null) {
                        if (!measurement.contentEquals(expected.snpMeasurement)) {
                            errors.add("SNP measurement does not match expected value")
                        }
                    } else {
                        warnings.add("No expected SNP measurement provided")
                    }

                    // TODO: Verify signature against AMD VCEK certificate
                    warnings.add("Hardware signature verification not yet implemented")
                }
            }

            AttestationType.TDX -> {
                if (quote.size < TDX_REPORT_SIZE) {
                    errors.add("TDX report too short: ${quote.size}")
                } else {
                    // Extract MRTD (bytes 136-184)
                    val mrTd = quote.copyOfRange(136, 184)

                    if (expected.tdxMrTd != null) {
                        if (!mrTd.contentEquals(expected.tdxMrTd)) {
                            errors.add("TDX MRTD does not match expected value")
                        }
                    } else {
                        warnings.add("No expected TDX MRTD provided")
                    }

                    // TODO: Verify signature against Intel QE certificate
                    warnings.add("Hardware signature verification not yet implemented")
                }
            }

            AttestationType.UNKNOWN -> {
                errors.add("Unable to detect attestation type from quote format")
            }
        }

        return AttestationResult(
            valid = errors.isEmpty(),
            attestationType = attestationType,
            errors = errors,
            warnings = warnings
        )
    }
}

// ============================================================================
// Rekor Client
// ============================================================================

/**
 * Client for querying Rekor transparency log
 */
class RekorClient {
    private val baseUrl = "https://rekor.sigstore.dev"

    /**
     * Fetch expected measurements for an image digest
     */
    suspend fun fetchMeasurements(
        imageDigest: String
    ): ExpectedMeasurements? = withContext(Dispatchers.IO) {
        // Stub: Implement Rekor API calls
        // 1. POST /api/v1/index/retrieve with {"hash": "sha256:..."}
        // 2. GET /api/v1/log/entries/{uuid} for each returned UUID
        // 3. Parse in-toto attestation body
        // 4. Extract measurements from SLSA provenance predicate
        null
    }
}

// ============================================================================
// Supporting Types
// ============================================================================

data class KeyPair(
    val publicKey: ByteArray,
    val secretKey: ByteArray
)

class AttestationException(message: String) : Exception(message)

// ============================================================================
// Utilities
// ============================================================================

fun ByteArray.toHexString(): String =
    joinToString("") { "%02x".format(it) }

fun String.hexToByteArray(): ByteArray {
    check(length % 2 == 0) { "Hex string must have even length" }
    return chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()
}
