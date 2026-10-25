package ru.qulogi.app

import android.content.Intent
import android.os.ParcelFileDescriptor
import io.flutter.plugin.common.MethodChannel
import mobile.Mobile

/// Bridges engine logs and VPN state changes to the Flutter side. Logs are
/// buffered so the UI can replay them after reconnecting (drainLogs).
object EngineBus {

    private const val MAX_BUFFER = 400
    private val buffer = ArrayDeque<String>()
    private val main = android.os.Handler(android.os.Looper.getMainLooper())

    @Volatile
    private var channel: MethodChannel? = null

    fun attach(ch: MethodChannel) {
        channel = ch
    }

    fun detach(ch: MethodChannel) {
        if (channel === ch) {
            channel = null
        }
    }

    fun addLog(line: String) {
        synchronized(buffer) {
            if (buffer.size >= MAX_BUFFER) buffer.removeFirst()
            buffer.addLast(line)
        }
        main.post { channel?.invokeMethod("log", line) }
    }

    fun sendState(state: String) {
        main.post { channel?.invokeMethod("vpnState", state) }
    }

    /// Forwards a qulogi:// deep link (invite) to the Flutter side.
    fun sendInvite(link: String) {
        main.post { channel?.invokeMethod("invite", link) }
    }

    fun drain(): List<String> = synchronized(buffer) { buffer.toList() }

    val sink: mobile.LogSink = mobile.LogSink { line -> addLog(line ?: "") }
}
