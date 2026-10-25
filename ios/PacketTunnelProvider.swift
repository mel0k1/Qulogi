// PacketTunnelProvider skeleton for the iOS port of Qulogi.
//
// STATUS: experimental scaffold — not built by CI yet. See ios/README.md
// for the full integration checklist (entitlements, gomobile bind for
// iOS, Xcode target wiring).
//
// The flow mirrors the Android design: the system hands us the packet
// flow via IPC, we feed it to the Go core through the gomobile bridge
// (mobile.ConfigureVPN / mobile.StartVPN) and the gVisor netstack inside
// the Go library does the rest.

import NetworkExtension
import Foundation

class PacketTunnelProvider: NEPacketTunnelProvider {

    private var started = false

    override func startTunnel(
        options: [String: NSObject]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        // 1. Advertise the routes the tunnel captures: default v4 + v6 and
        //    a DNS route so the system resolver goes through us.
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.111.0.1")
        settings.mtu = 8500
        settings.ipv4Settings = NEIPv4Settings(
            addresses: ["10.111.0.1"], subnetMasks: ["255.255.255.255"])
        settings.ipv4Settings?.includedRoutes = [
            NEIPv4Route(destinationAddress: "0.0.0.0", subnetMask: "0.0.0.0")
        ]
        settings.ipv6Settings = NEIPv6Settings(
            addresses: ["fd00:7175:6c6f:6769::1"], networkPrefixLengths: [128])
        settings.ipv6Settings?.includedRoutes = [
            NEIPv6Route(destinationAddress: "::", networkPrefixLength: 0)
        ]
        settings.dnsSettings = NEDNSSettings(servers: ["10.111.0.1"])

        setTunnelNetworkSettings(settings) { error in
            if let error {
                completionHandler(error)
                return
            }
            // 2. Bridge the packet flow into the Go core:
            //    - read IP packets from self.packetFlow, inject via the
            //      gomobile bridge (mobile.Mobile.startVPN with a packet
            //      reader callback, similar to libbox's iOS integration);
            //    - packets written back by the Go netstack go to
            //      packetFlow.writePackets.
            // 3. Configure: mobile.Mobile.setProtector(...) is not needed
            //    on iOS: NetworkExtension sockets are outside the tunnel
            //    by default.
            self.started = true
            completionHandler(nil)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        if started {
            mobile.Mobile.stopVPN()
            started = false
        }
        completionHandler()
    }

    override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)? = nil
    ) {
        // Status queries from the container app.
        completionHandler(mobile.Mobile.vpnStatus().data(using: .utf8))
    }
}
