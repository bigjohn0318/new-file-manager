package com.goodwy.filemanager.network

import java.io.File
import java.io.IOException

/**
 * Confines all FTP file operations to a single root directory.
 *
 * Every client-supplied path MUST be resolved through [resolve] before being used for
 * any file I/O. This is the single choke point that prevents path traversal: clients
 * cannot escape [root] no matter what they send (`..`, absolute paths, symlinks,
 * encoded separators, etc).
 *
 * Design notes:
 * - We resolve against the *canonical* (symlink-resolved, normalized) form of both the
 *   root and the candidate path, then verify the candidate's canonical path is either
 *   equal to root or nested under it with a path separator boundary. Canonicalization
 *   is what defeats symlink-based escapes; without it, a symlink inside root pointing
 *   outside it would let a client read/write arbitrary files.
 * - We never trust the client's path string directly for I/O — only the canonicalized
 *   [File] this function returns.
 * - A non-existent target (e.g. a file about to be created by STOR) cannot be
 *   canonicalized via its own missing path, so we canonicalize the deepest existing
 *   parent and re-attach the remaining (non-existent) segments before the boundary
 *   check. This still defeats traversal because each `..` segment is resolved
 *   structurally before any existence check happens.
 */
class FtpPathTraversalException(message: String) : Exception(message)

class FtpPathResolver(rootDir: File) {

    val root: File = rootDir.canonicalFile

    init {
        require(root.isDirectory) { "FTP root must be an existing directory: $root" }
    }

    /**
     * Resolves a client-supplied FTP path (e.g. from CWD, RETR, STOR, DELE, MKD, RMD,
     * LIST args) against [root]. The input may be absolute (FTP-absolute, i.e. relative
     * to the virtual FTP root) or relative to [currentDir].
     *
     * Throws [FtpPathTraversalException] if the resolved path would fall outside [root].
     * Never returns a [File] outside [root].
     */
    @Throws(FtpPathTraversalException::class, IOException::class)
    fun resolve(clientPath: String, currentDir: File = root): File {
        if (clientPath.contains('\u0000')) {
            throw FtpPathTraversalException("Null byte in path")
        }

        // Normalize separators; FTP clients should send '/' but be defensive.
        val normalizedInput = clientPath.replace('\\', '/')

        // Determine the base to resolve against: FTP-absolute paths are relative to
        // root, not to the filesystem root, and never to currentDir.
        val base = if (normalizedInput.startsWith("/")) root else currentDir

        // Build the raw (not-yet-canonical) target by manually walking segments so that
        // '..' is resolved structurally against our virtual root boundary rather than
        // relying on java.io.File's filesystem-level canonicalization alone (which would
        // happily walk above root before we get a chance to check).
        val segments = normalizedInput.split('/').filter { it.isNotEmpty() && it != "." }

        // Start from the segments of `base` relative to nothing — we walk on top of an
        // explicit stack seeded with base's own path components, but clamped: we only
        // allow '..' to pop segments that are *below* root, never pop root itself away.
        var cursor = base
        for (segment in segments) {
            if (segment == "..") {
                val parent = cursor.parentFile ?: cursor
                if (!isWithinOrEqual(parent, root)) {
                    // Reject outright. Do NOT clamp to root and keep consuming the
                    // remaining segments — that would silently remap an out-of-bounds
                    // request onto an unrelated in-root path instead of failing closed.
                    throw FtpPathTraversalException(
                        "Path traversal above root: input='$clientPath'"
                    )
                }
                cursor = parent
            } else {
                cursor = File(cursor, segment)
            }
        }

        val resolved = resolveWithoutRequiringExistence(cursor)

        if (!isWithinOrEqual(resolved, root)) {
            throw FtpPathTraversalException(
                "Resolved path escapes FTP root: input='$clientPath' resolved='$resolved' root='$root'"
            )
        }

        return resolved
    }

    /**
     * Canonicalizes [target] even if it (or trailing segments of it) doesn't exist yet,
     * by canonicalizing the deepest existing ancestor and re-appending the remaining
     * segments literally (those segments contain no '..' at this point — that was
     * already resolved structurally in [resolve]).
     */
    private fun resolveWithoutRequiringExistence(target: File): File {
        var existing = target
        val pending = ArrayDeque<String>()
        while (!existing.exists()) {
            val name = existing.name
            if (name.isEmpty()) break
            pending.addFirst(name)
            existing = existing.parentFile ?: break
        }
        var canonical = existing.canonicalFile
        for (name in pending) {
            canonical = File(canonical, name)
        }
        return canonical
    }

    /** True if [candidate]'s canonical-ish path is [boundary] or nested under it. */
    private fun isWithinOrEqual(candidate: File, boundary: File): Boolean {
        val candidatePath = candidate.path.let { if (it.endsWith(File.separator)) it else it + File.separator }
        val boundaryPath = boundary.path.let { if (it.endsWith(File.separator)) it else it + File.separator }
        return candidatePath == boundaryPath || candidatePath.startsWith(boundaryPath) || candidate.path == boundary.path
    }
}
