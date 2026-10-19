package com.mekari.securityagent

import java.io.ByteArrayOutputStream
import java.io.InputStream
import android.os.Build
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.atomic.AtomicBoolean

internal data class RootResult(val exitCode: Int, val stdout: String, val stderr: String)

/** Executes only locally-authored, fixed-purpose root commands. Never log scripts or output. */
internal class RootShell {
    private val current = AtomicReference<Process?>(null)
    private val cancelRequested = AtomicBoolean(false)

    fun run(script: String, timeoutMs: Long = DEFAULT_TIMEOUT_MS): RootResult {
        require(script.isNotBlank()) { "Root command is empty" }
        require(timeoutMs in 1..MAX_TIMEOUT_MS) { "Root command timeout is outside the permitted range" }
        cancelRequested.set(false)
        val process = try {
            startRootProcess(script)
        } catch (e: Exception) {
            throw IllegalStateException("Unable to start root command", e)
        }
        if (!current.compareAndSet(null, process)) {
            terminate(process)
            process.inputStream.closeQuietly()
            process.errorStream.closeQuietly()
            process.outputStream.closeQuietly()
            throw IllegalStateException("A root command is already running")
        }
        if (cancelRequested.get()) terminate(process)
        process.outputStream.closeQuietly()
        val out = BoundedDrain(process.inputStream)
        val err = BoundedDrain(process.errorStream)
        val outThread = Thread(out, "root-stdout").apply { isDaemon = true; start() }
        val errThread = Thread(err, "root-stderr").apply { isDaemon = true; start() }
        try {
            val exit = waitForExit(process, timeoutMs)
            if (cancelRequested.get()) throw IllegalStateException("Root command cancelled")
            if (exit == null) {
                terminate(process)
                throw IllegalStateException("Root command timed out")
            }
            outThread.join(DRAIN_JOIN_MS)
            errThread.join(DRAIN_JOIN_MS)
            if (outThread.isAlive || errThread.isAlive) throw IllegalStateException("Root command output did not close")
            val drainError = out.failure.get() ?: err.failure.get()
            if (drainError != null) throw IllegalStateException("Unable to read root command output", drainError)
            return RootResult(exit, out.text(), err.text())
        } catch (e: InterruptedException) {
            terminate(process)
            Thread.currentThread().interrupt()
            throw IllegalStateException("Root command interrupted", e)
        } finally {
            current.compareAndSet(process, null)
            process.inputStream.closeQuietly()
            process.errorStream.closeQuietly()
            process.outputStream.closeQuietly()
        }
    }
    private fun startRootProcess(script: String): Process {
        var lastError: java.io.IOException? = null
        for (binary in ROOT_BINARIES) {
            try {
                return ProcessBuilder(binary, "-c", script).start()
            } catch (e: java.io.IOException) {
                lastError = e
            }
        }
        throw lastError ?: java.io.IOException("No root shell executable is available")
    }


    fun cancel() {
        cancelRequested.set(true)
        current.get()?.let(::terminate)
    }

    private fun waitForExit(process: Process, timeoutMs: Long): Int? {
        val deadline = System.nanoTime() + timeoutMs * 1_000_000L
        while (true) {
            try {
                return process.exitValue()
            } catch (_: IllegalThreadStateException) {
                val remaining = deadline - System.nanoTime()
                if (remaining <= 0) return null
                Thread.sleep(minOf(25L, (remaining / 1_000_000L).coerceAtLeast(1L)))
            }
        }
    }

    private fun terminate(process: Process) {
        process.destroy()
        if (waitForExit(process, TERMINATION_GRACE_MS) == null && Build.VERSION.SDK_INT >= 26) {
            process.destroyForcibly()
        }
    }

    fun forceStopPackage(packageName: String): RootResult {
        require(PACKAGE_PATTERN.matches(packageName)) { "Invalid target package name" }
        return run("am force-stop --user 0 ${quote(packageName)}")
    }

    companion object {
        private const val DEFAULT_TIMEOUT_MS = 10_000L
        private const val MAX_TIMEOUT_MS = 30_000L
        private const val MAX_OUTPUT_BYTES = 65_536
        private const val DRAIN_JOIN_MS = 1_000L
        private const val TERMINATION_GRACE_MS = 250L
        private val PACKAGE_PATTERN = Regex("[A-Za-z_][A-Za-z0-9_]*(?:\\.[A-Za-z_][A-Za-z0-9_]*)+")
        private val ROOT_BINARIES = listOf("/system_ext/bin/su", "/system/bin/su", "/system/xbin/su", "su")

        fun quote(value: String): String {
            require(value.indexOf('\u0000') < 0) { "NUL is not permitted in shell arguments" }
            return "'" + value.replace("'", "'\\''") + "'"
        }
    }

    private class BoundedDrain(private val input: InputStream) : Runnable {
        private val bytes = ByteArrayOutputStream()
        val failure = AtomicReference<Throwable?>(null)

        override fun run() {
            val buffer = ByteArray(4096)
            try {
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    val keep = (MAX_OUTPUT_BYTES - bytes.size()).coerceAtLeast(0).coerceAtMost(n)
                    if (keep > 0) bytes.write(buffer, 0, keep)
                }
            } catch (e: Exception) {
                failure.compareAndSet(null, e)
            }
        }

        @Synchronized fun text(): String = bytes.toString(Charsets.UTF_8.name())
    }
}

private fun java.io.Closeable.closeQuietly() {
    try { close() } catch (_: Exception) { }
}
