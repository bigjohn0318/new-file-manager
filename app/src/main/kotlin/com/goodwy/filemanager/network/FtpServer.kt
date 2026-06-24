package com.goodwy.filemanager.network

import java.io.BufferedReader
import java.io.File
import java.io.IOException
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.charset.StandardCharsets
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * A minimal, from-scratch FTP server covering a deliberately small RFC959 subset:
 * USER, PASS, QUIT, PWD, CWD, CDUP, TYPE, PASV, LIST, NLST, RETR, STOR, DELE, MKD, RMD,
 * SYST, FEAT, NOOP.
 *
 * Explicitly NOT implemented (by design, not oversight): active mode (PORT), anonymous
 * login, FTPS/TLS, REST (resume), RNFR/RNTO (rename), APPE (append), site commands.
 * Plain FTP is unencrypted — credentials and file contents are sent in clear text. This
 * is surfaced to the user in the UI; it is not meant for untrusted networks.
 *
 * Every filesystem-touching command resolves its path argument through
 * [FtpPathResolver.resolve] before touching disk. This is the single security-critical
 * invariant of this class — do not add a code path that uses a client-supplied path
 * string directly against [File] without going through the resolver first.
 *
 * Threading model: one thread per connection (acceptor thread + a fixed-size pool for
 * sessions). This is intentionally simple over performant — a phone-local FTP server
 * serving a handful of concurrent transfers does not need an async/NIO design, and a
 * simple blocking model is much easier to reason about for correctness.
 */
class FtpServer(
    private val root: File,
    private val credential: FtpCredential,
    private val controlPort: Int = 2121,
    private val onLog: (String) -> Unit = {},
) {
    private val resolver = FtpPathResolver(root)
    private var serverSocket: ServerSocket? = null
    private val running = AtomicBoolean(false)
    private val executor = Executors.newCachedThreadPool()
    private val acceptorExecutor = Executors.newSingleThreadExecutor()
    private val activeSessions = CopyOnWriteArrayList<FtpSession>()

    val isRunning: Boolean get() = running.get()
    val boundPort: Int get() = serverSocket?.localPort ?: -1

    @Throws(IOException::class)
    fun start() {
        if (running.get()) return
        val socket = ServerSocket(controlPort, 50, InetAddress.getByName("0.0.0.0"))
        serverSocket = socket
        running.set(true)
        acceptorExecutor.submit {
            while (running.get()) {
                try {
                    val client = socket.accept()
                    val session = FtpSession(client, resolver, credential, root, onLog)
                    activeSessions.add(session)
                    executor.submit {
                        try {
                            session.serve()
                        } finally {
                            activeSessions.remove(session)
                        }
                    }
                } catch (e: IOException) {
                    if (running.get()) onLog("Accept loop error: ${e.message}")
                }
            }
        }
    }

    fun stop() {
        running.set(false)
        try {
            serverSocket?.close()
        } catch (e: IOException) {
            // best effort
        }
        activeSessions.forEach { it.close() }
        activeSessions.clear()
        executor.shutdownNow()
        acceptorExecutor.shutdownNow()
    }
}

/**
 * One control-channel connection. Each client gets its own [FtpAuthState] and its own
 * notion of "current directory" — both are connection-scoped, never shared.
 */
internal class FtpSession(
    private val controlSocket: Socket,
    private val resolver: FtpPathResolver,
    credential: FtpCredential,
    private val root: File,
    private val onLog: (String) -> Unit,
) {
    private val authState = FtpAuthState(credential)
    private var currentDir: File = resolver.root
    private var dataServerSocket: ServerSocket? = null
    private val closed = AtomicBoolean(false)
    private var binaryMode = true

    private val writer = controlSocket.getOutputStream()
    private val reader = BufferedReader(InputStreamReader(controlSocket.getInputStream(), StandardCharsets.UTF_8))

    fun close() {
        if (closed.compareAndSet(false, true)) {
            try { dataServerSocket?.close() } catch (e: IOException) {}
            try { controlSocket.close() } catch (e: IOException) {}
        }
    }

    fun serve() {
        try {
            controlSocket.soTimeout = 5 * 60 * 1000 // 5 min idle timeout
            send(220, "Goodwy File Manager FTP ready")
            while (!closed.get()) {
                val line = try {
                    reader.readLine() ?: break
                } catch (e: SocketTimeoutException) {
                    send(421, "Idle timeout, closing connection")
                    break
                }
                if (line.isBlank()) continue
                handleCommand(line)
            }
        } catch (e: IOException) {
            onLog("Session error: ${e.message}")
        } finally {
            close()
        }
    }

    private fun handleCommand(line: String) {
        val spaceIdx = line.indexOf(' ')
        val verb = (if (spaceIdx == -1) line else line.substring(0, spaceIdx)).uppercase()
        val arg = if (spaceIdx == -1) "" else line.substring(spaceIdx + 1).trim()

        // Commands allowed pre-authentication.
        when (verb) {
            "USER" -> { handleUser(arg); return }
            "PASS" -> { handlePass(arg); return }
            "QUIT" -> { send(221, "Goodbye"); close(); return }
            "FEAT" -> { send(211, "no-features"); return }
            "SYST" -> { send(215, "UNIX Type: L8"); return }
            "NOOP" -> { send(200, "OK"); return }
        }

        if (!authState.requireAuthenticated()) {
            send(530, "Not logged in")
            return
        }

        when (verb) {
            "PWD" -> handlePwd()
            "CWD" -> handleCwd(arg)
            "CDUP" -> handleCwd("..")
            "TYPE" -> handleType(arg)
            "PASV" -> handlePasv()
            "LIST", "NLST" -> handleList(arg, verb == "NLST")
            "RETR" -> handleRetr(arg)
            "STOR" -> handleStor(arg)
            "DELE" -> handleDele(arg)
            "MKD", "XMKD" -> handleMkd(arg)
            "RMD", "XRMD" -> handleRmd(arg)
            else -> send(502, "Command not implemented")
        }
    }

    private fun handleUser(arg: String) {
        if (authState.onUser(arg)) {
            send(331, "Password required")
        } else {
            send(530, "Anonymous access not permitted")
        }
    }

    private fun handlePass(arg: String) {
        if (authState.isLockedOut) {
            send(530, "Too many failed attempts, connection will be closed")
            close()
            return
        }
        if (authState.onPass(arg)) {
            send(230, "Login successful")
        } else {
            if (authState.isLockedOut) {
                send(530, "Too many failed attempts, connection will be closed")
                close()
            } else {
                send(530, "Login incorrect")
            }
        }
    }

    private fun handlePwd() {
        val rel = relativePath(currentDir)
        send(257, "\"$rel\" is the current directory")
    }

    private fun handleCwd(arg: String) {
        try {
            val target = resolver.resolve(arg, currentDir)
            if (!target.isDirectory) {
                send(550, "Not a directory")
                return
            }
            currentDir = target
            send(250, "Directory changed to ${relativePath(target)}")
        } catch (e: FtpPathTraversalException) {
            send(550, "Permission denied")
        }
    }

    private fun handleType(arg: String) {
        binaryMode = arg.equals("I", ignoreCase = true)
        send(200, "Type set")
    }

    private fun handlePasv() {
        try {
            dataServerSocket?.close()
            val dataSocket = ServerSocket(0, 1, InetAddress.getByName("0.0.0.0"))
            dataServerSocket = dataSocket
            val port = dataSocket.localPort
            val localAddr = controlSocket.localAddress.hostAddress?.replace(".", ",") ?: "127,0,0,1"
            val p1 = port / 256
            val p2 = port % 256
            send(227, "Entering Passive Mode ($localAddr,$p1,$p2)")
        } catch (e: IOException) {
            send(425, "Cannot open data connection")
        }
    }

    private fun acceptDataConnection(): Socket? {
        val server = dataServerSocket ?: run { send(425, "Use PASV first"); return null }
        return try {
            server.soTimeout = 30_000
            server.accept()
        } catch (e: IOException) {
            send(425, "Data connection failed: ${e.message}")
            null
        }
    }

    private fun handleList(arg: String, namesOnly: Boolean) {
        val target = try {
            if (arg.isBlank()) currentDir else resolver.resolve(arg, currentDir)
        } catch (e: FtpPathTraversalException) {
            send(550, "Permission denied")
            return
        }
        if (!target.isDirectory) {
            send(550, "Not a directory")
            return
        }
        send(150, "Opening data connection for directory listing")
        val data = acceptDataConnection() ?: return
        try {
            data.getOutputStream().use { out ->
                val entries = target.listFiles()?.sortedBy { it.name } ?: emptyList()
                for (entry in entries) {
                    val lineOut = if (namesOnly) {
                        entry.name + "\r\n"
                    } else {
                        formatListLine(entry) + "\r\n"
                    }
                    out.write(lineOut.toByteArray(StandardCharsets.UTF_8))
                }
            }
            send(226, "Transfer complete")
        } catch (e: IOException) {
            send(426, "Connection closed; transfer aborted")
        } finally {
            try { data.close() } catch (e: IOException) {}
        }
    }

    private fun formatListLine(f: File): String {
        val type = if (f.isDirectory) "d" else "-"
        val perms = "rwxr--r--"
        val size = f.length()
        val name = f.name
        return "$type$perms 1 owner group $size Jan 1 00:00 $name"
    }

    private fun handleRetr(arg: String) {
        val target = try {
            resolver.resolve(arg, currentDir)
        } catch (e: FtpPathTraversalException) {
            send(550, "Permission denied")
            return
        }
        if (!target.isFile) {
            send(550, "File not found")
            return
        }
        send(150, "Opening data connection for file transfer")
        val data = acceptDataConnection() ?: return
        try {
            target.inputStream().use { input ->
                data.getOutputStream().use { out: OutputStream ->
                    input.copyTo(out)
                }
            }
            send(226, "Transfer complete")
        } catch (e: IOException) {
            send(426, "Connection closed; transfer aborted")
        } finally {
            try { data.close() } catch (e: IOException) {}
        }
    }

    private fun handleStor(arg: String) {
        val target = try {
            resolver.resolve(arg, currentDir)
        } catch (e: FtpPathTraversalException) {
            send(550, "Permission denied")
            return
        }
        // Re-validate parent dir is within root (defense in depth; resolver already
        // guarantees this, but STOR creates a new file so we double-check the parent
        // exists and is a real directory before writing).
        val parent = target.parentFile
        if (parent == null || !parent.isDirectory) {
            send(550, "Target directory does not exist")
            return
        }
        send(150, "Opening data connection for file transfer")
        val data = acceptDataConnection() ?: return
        try {
            data.getInputStream().use { input ->
                target.outputStream().use { out ->
                    input.copyTo(out)
                }
            }
            send(226, "Transfer complete")
        } catch (e: IOException) {
            send(426, "Connection closed; transfer aborted")
        } finally {
            try { data.close() } catch (e: IOException) {}
        }
    }

    private fun handleDele(arg: String) {
        val target = try {
            resolver.resolve(arg, currentDir)
        } catch (e: FtpPathTraversalException) {
            send(550, "Permission denied")
            return
        }
        if (!target.isFile) {
            send(550, "File not found")
            return
        }
        if (target.delete()) send(250, "File deleted") else send(550, "Delete failed")
    }

    private fun handleMkd(arg: String) {
        val target = try {
            resolver.resolve(arg, currentDir)
        } catch (e: FtpPathTraversalException) {
            send(550, "Permission denied")
            return
        }
        if (target.exists()) {
            send(550, "Already exists")
            return
        }
        if (target.mkdir()) send(257, "\"${relativePath(target)}\" created") else send(550, "Create failed")
    }

    private fun handleRmd(arg: String) {
        val target = try {
            resolver.resolve(arg, currentDir)
        } catch (e: FtpPathTraversalException) {
            send(550, "Permission denied")
            return
        }
        if (target == resolver.root) {
            send(550, "Cannot remove root directory")
            return
        }
        if (!target.isDirectory) {
            send(550, "Not a directory")
            return
        }
        if (target.delete()) send(250, "Directory removed") else send(550, "Remove failed (not empty?)")
    }

    private fun relativePath(target: File): String {
        val rel = target.path.removePrefix(resolver.root.path)
        return if (rel.isEmpty()) "/" else rel.replace(File.separatorChar, '/').let { if (it.startsWith("/")) it else "/$it" }
    }

    private fun send(code: Int, message: String) {
        val line = "$code $message\r\n"
        try {
            writer.write(line.toByteArray(StandardCharsets.UTF_8))
            writer.flush()
        } catch (e: IOException) {
            onLog("Failed to send response: ${e.message}")
        }
    }
}
