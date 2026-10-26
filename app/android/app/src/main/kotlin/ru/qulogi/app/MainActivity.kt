package ru.qulogi.app

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import mobile.Mobile
import java.util.concurrent.Executors

class MainActivity : FlutterActivity() {

    companion object {
        private const val CHANNEL = "qulogi/engine"
        private const val REQUEST_VPN = 4711
    }

    private val goExecutor = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())

    private var pendingVpnConfig: String? = null
    private var pendingVpnResult: MethodChannel.Result? = null

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        forwardInvite(intent)
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        val channel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
        EngineBus.attach(channel)
        channel.setMethodCallHandler { call, result ->
            when (call.method) {
                "start" -> onGo(result) {
                    Mobile.configure(call.arguments<String>())
                    Mobile.start()
                    null
                }
                "stop" -> onGo(result) {
                    Mobile.stop()
                    null
                }
                "status" -> onGo(result) { Mobile.status() }
                "startVpn" -> startVpnFlow(call.arguments<String>(), result)
                "stopVpn" -> stopVpn(result)
                "vpnStatus" -> onGo(result) { Mobile.vpnStatus() }
                "drainLogs" -> result.success(EngineBus.drain())
                "fetchDirectory" -> onGo(result, "discover") {
                    Mobile.fetchDirectory(call.arguments<String>())
                }
                else -> result.notImplemented()
            }
        }
    }

    // Go calls block: on the main thread they freeze input and end in an
    // ANR kill. Replies must return through the main looper.
    private fun onGo(result: MethodChannel.Result, code: String = "engine", work: () -> Any?) {
        goExecutor.execute {
            val reply = runCatching { work() }
            mainHandler.post {
                reply.fold(
                    onSuccess = { result.success(it) },
                    onFailure = { result.error(code, it.message ?: "error", null) },
                )
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        forwardInvite(intent)
    }

    private fun forwardInvite(intent: Intent?) {
        val data = intent?.data ?: return
        if (data.scheme == "qulogi") {
            EngineBus.sendInvite(data.toString())
        }
    }

    private fun startVpnFlow(config: String?, result: MethodChannel.Result) {
        if (config == null) {
            result.error("args", "config required", null)
            return
        }
        val prep = VpnService.prepare(this)
        if (prep != null) {
            pendingVpnConfig = config
            pendingVpnResult = result
            startActivityForResult(prep, REQUEST_VPN)
        } else {
            doStartVpn(config)
            result.success(null)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN) {
            val result = pendingVpnResult
            pendingVpnResult = null
            val config = pendingVpnConfig
            pendingVpnConfig = null
            if (resultCode == RESULT_OK && config != null) {
                doStartVpn(config)
                result?.success(null)
            } else {
                result?.error("vpn_denied", "VPN permission denied", null)
            }
        }
    }

    private fun doStartVpn(config: String) {
        goExecutor.execute { runCatching { Mobile.setBlocked(false) } }
        val intent = Intent(this, QulogiVpnService::class.java)
            .putExtra(QulogiVpnService.EXTRA_CONFIG, config)
        startForegroundService(intent)
    }

    private fun stopVpn(result: MethodChannel.Result) {
        val prefs = getSharedPreferences("FlutterSharedPreferences", MODE_PRIVATE)
        val killSwitch = prefs.getBoolean("flutter.killswitch", false)
        onGo(result) {
            if (killSwitch && Mobile.vpnStatus() != "{}") {
                Mobile.setBlocked(true)
                EngineBus.sendState("blocked")
            } else {
                Mobile.stopVPN()
                stopService(Intent(this, QulogiVpnService::class.java))
                EngineBus.sendState("stopped")
            }
            null
        }
    }
}
