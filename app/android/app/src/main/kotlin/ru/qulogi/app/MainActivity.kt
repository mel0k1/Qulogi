package ru.qulogi.app

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import mobile.Mobile

class MainActivity : FlutterActivity() {

    companion object {
        private const val CHANNEL = "qulogi/engine"
        private const val REQUEST_VPN = 4711
    }

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
                "start" -> try {
                    Mobile.configure(call.arguments<String>())
                    Mobile.start()
                    result.success(null)
                } catch (e: Exception) {
                    result.error("engine", e.message, null)
                }
                "stop" -> {
                    Mobile.stop()
                    result.success(null)
                }
                "status" -> result.success(Mobile.status())
                "startVpn" -> startVpnFlow(call.arguments<String>(), result)
                "stopVpn" -> stopVpn(result)
                "vpnStatus" -> result.success(Mobile.vpnStatus())
                "drainLogs" -> result.success(EngineBus.drain())
                "fetchDirectory" -> try {
                    result.success(Mobile.fetchDirectory(call.arguments<String>()))
                } catch (e: Exception) {
                    result.error("discover", e.message, null)
                }
                else -> result.notImplemented()
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
        Mobile.setBlocked(false)
        val intent = Intent(this, QulogiVpnService::class.java)
            .putExtra(QulogiVpnService.EXTRA_CONFIG, config)
        startForegroundService(intent)
    }

    private fun stopVpn(result: MethodChannel.Result) {
        val prefs = getSharedPreferences("FlutterSharedPreferences", MODE_PRIVATE)
        val killSwitch = prefs.getBoolean("flutter.killswitch", false)
        if (killSwitch && Mobile.vpnStatus() != "{}") {
            // Keep the TUN interface up and black-hole every new flow so
            // nothing can leak while the user thinks traffic is protected.
            Mobile.setBlocked(true)
            EngineBus.sendState("blocked")
        } else {
            Mobile.stopVPN()
            stopService(Intent(this, QulogiVpnService::class.java))
            EngineBus.sendState("stopped")
        }
        result.success(null)
    }
}
