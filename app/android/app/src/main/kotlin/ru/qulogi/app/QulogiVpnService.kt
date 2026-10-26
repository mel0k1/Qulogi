package ru.qulogi.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import mobile.Mobile
import java.util.concurrent.Executors

class QulogiVpnService : VpnService() {

    companion object {
        const val EXTRA_CONFIG = "ru.qulogi.app.CONFIG"
        private const val CHANNEL_ID = "qulogi_vpn"
        private const val NOTIF_ID = 1
        private const val DEFAULT_MTU = 8500
    }

    private val goExecutor = Executors.newSingleThreadExecutor()
    private var tun: ParcelFileDescriptor? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
        startForeground(NOTIF_ID, buildNotification("Starting…"))
        Mobile.setLogSink(EngineBus.sink)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val config = intent?.getStringExtra(EXTRA_CONFIG)
        if (config == null) {
            stopSelf()
            return START_NOT_STICKY
        }
        goExecutor.execute { startVpn(config) }
        return START_STICKY
    }

    private fun startVpn(config: String) {
        try {
            Mobile.setProtector { fd -> protect(fd) }
            Mobile.configureVPN(config)

            val mtu = runCatching {
                org.json.JSONObject(config).optInt("mtu", DEFAULT_MTU)
            }.getOrDefault(DEFAULT_MTU)

            val builder = Builder()
                .setSession("Qulogi")
                .setMtu(mtu)
                .addAddress("10.111.0.1", 32)
                .addRoute("0.0.0.0", 0)
                .addAddress("fd00:7175:6c6f:6769::1", 128)
                .addRoute("::", 0)
                .addDnsServer("10.111.0.1")
                .setBlocking(true)

            val pfd = builder.establish()
            if (pfd == null) {
                EngineBus.addLog("vpn: establish() denied")
                EngineBus.sendState("error")
                stopSelf()
                return
            }
            tun = pfd
            Mobile.startVPN(pfd.detachFd(), mtu)
            EngineBus.sendState("connected")
            updateNotification("Protected")
        } catch (e: Exception) {
            EngineBus.addLog("vpn: ${e.message}")
            EngineBus.sendState("error")
            stopSelf()
        }
    }

    override fun onRevoke() {
        goExecutor.execute {
            Mobile.stopVPN()
            EngineBus.sendState("stopped")
        }
        stopSelf()
    }

    override fun onDestroy() {
        goExecutor.execute { Mobile.stopVPN() }
        super.onDestroy()
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val ch = NotificationChannel(
                CHANNEL_ID,
                "Qulogi tunnel",
                NotificationManager.IMPORTANCE_LOW,
            )
            ch.setShowBadge(false)
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(ch)
        }
    }

    private fun buildNotification(text: String): Notification {
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val b = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return b
            .setContentTitle("Qulogi")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setContentIntent(pi)
            .build()
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIF_ID, buildNotification(text))
    }
}
