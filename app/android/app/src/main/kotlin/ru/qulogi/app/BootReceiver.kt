package ru.qulogi.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService

/// Starts the VPN tunnel after boot when the user enabled auto-start in
/// Qulogi settings (off by default). Flutter's shared_preferences stores
/// values in the "FlutterSharedPreferences" file with a "flutter." prefix.
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val action = intent.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED &&
            action != "android.intent.action.QUICKBOOT_POWERON"
        ) {
            return
        }
        val prefs = context.getSharedPreferences("FlutterSharedPreferences", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("flutter.autostart", false)) {
            return
        }
        val config = prefs.getString("flutter.engine_config", null) ?: return
        if (VpnService.prepare(context) != null) {
            // Permission was never granted (or revoked): silently skip.
            return
        }
        val service = Intent(context, QulogiVpnService::class.java)
            .putExtra(QulogiVpnService.EXTRA_CONFIG, config)
        context.startForegroundService(service)
    }
}
