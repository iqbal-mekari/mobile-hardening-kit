package com.mekari.securityagent

import android.app.KeyguardManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class AgentService : Service() {
    private val executor = Executors.newSingleThreadExecutor()
    private val active = AtomicBoolean(false)
    @Volatile private var controller: SessionController? = null
    @Volatile private var wakeLock: PowerManager.WakeLock? = null

    override fun onCreate() {
        super.onCreate()
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= 26) manager.createNotificationChannel(NotificationChannel(CHANNEL, getString(R.string.notification_channel), NotificationManager.IMPORTANCE_LOW))
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (val action = intent?.action) {
            ACTION_PAUSE, ACTION_STOP -> {
                val current = synchronized(workerLock) { workerOwner?.controller }
                if (action == ACTION_PAUSE) current?.requestPause() else current?.requestStop()
                if (!active.get()) stopSelf(startId)
            }
            ACTION_START, ACTION_RESUME -> startSession(intent.getStringExtra(EXTRA_SESSION_ID))
            else -> { stopSelf(startId); return START_NOT_STICKY }
        }
        return START_NOT_STICKY
    }

    @Synchronized private fun startSession(id: String?) {
        if (active.get()) return
        if (!claimWorker()) {
            stopSelf()
            return
        }
        var submitted = false
        try {
            val repository = AgentRepository(this)
            val record = id?.let { repository.readSession(it) } ?: repository.latestSession()
            if (record == null) return
            val keyguard = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            val power = getSystemService(Context.POWER_SERVICE) as PowerManager
            if (keyguard.isKeyguardLocked || !power.isInteractive) {
                repository.saveSession(record.copy(status = SessionStatus.PAUSED, message = "Unlock the device and reopen the assessment. No lockscreen action was attempted."))
                return
            }
            active.set(true)
            startForeground(NOTIFICATION_ID, notification("Preparing authorized assessment"))
            val lock = power.newWakeLock(PowerManager.FULL_WAKE_LOCK, "$packageName:assessment")
            lock.setReferenceCounted(false)
            lock.acquire(MAX_WAKELOCK_MS)
            wakeLock = lock
            val device = AndroidDeviceGateway(this)
            val runController = SessionController(repository, device)
            controller = runController
            executor.execute {
                try {
                    runController.run(record.id) { update ->
                        (getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager).notify(NOTIFICATION_ID, notification("${update.status}: ${update.message}"))
                    }
                } catch (failure: Exception) {
                    val latest = repository.readSession(record.id)
                    if (latest != null) repository.saveSession(latest.copy(status = SessionStatus.FAILED, message = failure.message ?: "Assessment failed"))
                } finally {
                    finishSession()
                }
            }
            submitted = true
        } finally {
            if (!submitted) finishSession()
        }
    }

    private fun claimWorker(): Boolean = synchronized(workerLock) {
        if (workerOwner != null) {
            false
        } else {
            workerOwner = this
            isRunning = true
            true
        }
    }

    @Synchronized private fun finishSession() {
        controller = null
        try {
            releaseWakeLock()
        } finally {
            try {
                stopForeground(true)
                stopSelf()
            } finally {
                active.set(false)
                synchronized(workerLock) {
                    if (workerOwner === this) {
                        workerOwner = null
                        isRunning = false
                    }
                }
            }
        }
    }
    private fun notification(message: String): Notification {
        val open = PendingIntent.getActivity(this, 1, Intent(this, MainActivity::class.java), pendingFlags())
        val pause = actionPending(ACTION_PAUSE, 2)
        val stop = actionPending(ACTION_STOP, 3)
        val builder = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, CHANNEL) else Notification.Builder(this)
        builder.setSmallIcon(android.R.drawable.ic_menu_search).setContentTitle("Security assessment")
            .setContentText(message.take(180)).setContentIntent(open).setOngoing(active.get())
            .addAction(Notification.Action.Builder(android.graphics.drawable.Icon.createWithResource(this, android.R.drawable.ic_media_pause), "Pause", pause).build())
            .addAction(Notification.Action.Builder(android.graphics.drawable.Icon.createWithResource(this, android.R.drawable.ic_menu_close_clear_cancel), "Stop", stop).build())
        return builder.build()
    }

    private fun actionPending(action: String, request: Int) = PendingIntent.getService(this, request, Intent(this, AgentService::class.java).setAction(action), pendingFlags())
    private fun pendingFlags() = PendingIntent.FLAG_UPDATE_CURRENT or if (Build.VERSION.SDK_INT >= 23) PendingIntent.FLAG_IMMUTABLE else 0
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onDestroy() {
        controller?.requestStop()
        // Let an already-submitted worker run its finally block before releasing its process lease.
        executor.shutdown()
        super.onDestroy()
    }

    @Synchronized private fun releaseWakeLock() {
        val lock = wakeLock
        wakeLock = null
        if (lock?.isHeld == true) lock.release()
    }

    companion object {
        const val ACTION_START = "com.mekari.securityagent.START"
        const val ACTION_RESUME = "com.mekari.securityagent.RESUME"
        const val ACTION_PAUSE = "com.mekari.securityagent.PAUSE"
        const val ACTION_STOP = "com.mekari.securityagent.STOP"
        const val EXTRA_SESSION_ID = "session_id"
        @Volatile var isRunning: Boolean = false
        private val workerLock = Any()
        private var workerOwner: AgentService? = null
        private const val CHANNEL = "assessment"
        private const val NOTIFICATION_ID = 716
        private const val MAX_WAKELOCK_MS = 60L * 60L * 1000L
    }
}
