package com.goodwy.filemanager.network

import java.security.SecureRandom

/**
 * Generates and checks the per-session FTP credential.
 *
 * Design choices (deliberate, do not "simplify" without re-reviewing):
 * - No anonymous access. A username is required but its value is not checked beyond
 *   non-blank — the PIN is the actual secret.
 * - The PIN is regenerated every time the server starts (not persisted), is shown to
 *   the user in the Network tab UI, and is never logged.
 * - Uses [SecureRandom], not [kotlin.random.Random], since this is a real credential
 *   guarding read/write filesystem access over the network.
 * - Comparison is constant-time-ish via a manual loop to avoid trivial timing leaks on
 *   PIN comparison. This isn't bulletproof against a sophisticated timing attack over a
 *   real network, but it costs nothing and removes the cheapest version of the leak.
 */
class FtpCredential private constructor(val pin: String) {

    companion object {
        private const val PIN_LENGTH = 8
        private const val PIN_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ" // no 0/O/1/I ambiguity
        private val random = SecureRandom()

        fun generate(): FtpCredential {
            val sb = StringBuilder(PIN_LENGTH)
            repeat(PIN_LENGTH) {
                sb.append(PIN_ALPHABET[random.nextInt(PIN_ALPHABET.length)])
            }
            return FtpCredential(sb.toString())
        }
    }

    fun matches(suppliedPin: String): Boolean {
        if (suppliedPin.length != pin.length) return false
        var diff = 0
        for (i in pin.indices) {
            diff = diff or (pin[i].code xor suppliedPin[i].code)
        }
        return diff == 0
    }
}

/**
 * Per-connection authentication state. One instance per accepted control-channel
 * connection; not shared across clients.
 */
class FtpAuthState(private val credential: FtpCredential) {

    var username: String? = null
        private set

    var isAuthenticated: Boolean = false
        private set

    /** Maximum failed PIN attempts before this connection is permanently rejected. */
    private var failedAttempts = 0
    private val maxFailedAttempts = 5

    var isLockedOut: Boolean = false
        private set

    fun onUser(name: String): Boolean {
        if (isLockedOut) return false
        // Reject blank/anonymous usernames outright — no anonymous access.
        if (name.isBlank() || name.equals("anonymous", ignoreCase = true)) {
            return false
        }
        username = name
        isAuthenticated = false
        return true
    }

    /** Returns true if authentication succeeded. */
    fun onPass(suppliedPin: String): Boolean {
        if (isLockedOut || username == null) return false

        if (credential.matches(suppliedPin)) {
            isAuthenticated = true
            failedAttempts = 0
            return true
        }

        failedAttempts++
        if (failedAttempts >= maxFailedAttempts) {
            isLockedOut = true
            isAuthenticated = false
        }
        return false
    }

    /** Every command other than USER/PASS/QUIT/feature-negotiation must check this. */
    fun requireAuthenticated(): Boolean = isAuthenticated && !isLockedOut
}
