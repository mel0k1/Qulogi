package cdnfront

import "strings"

// Profile describes a real CDN network a relay can be parked behind.
// WebSockets is the working condition; Frontable marks networks known to
// route by Host without cross-checking SNI (classic fronting, best effort).
type Profile struct {
	Name       string
	Title      string
	WebSockets bool
	Frontable  bool
	Note       string
}

// Profiles covers the real CDN networks with WS proxying the transport is
// designed against. Same-host camo (SNI=Host) works on every one.
var Profiles = []Profile{
	{"cloudflare", "Cloudflare", true, false, "park the relay zone behind the CDN, proxy WS to origin"},
	{"cloudfront", "Amazon CloudFront", true, false, "enable WebSocket on the distribution; idle WS ~60s"},
	{"gcore", "Gcore", true, false, "WS on CDN resources"},
	{"selectel", "Selectel CDN", true, false, "enable the WebSocket option on the resource"},
	{"yandex-cloud", "Yandex Cloud CDN", true, false, "WS to a custom origin; whitelisted Yandex ranges"},
	{"vk-cloud", "VK Cloud (MCS)", true, false, "VK/Mail.ru ranges are broadly whitelisted"},
}

func LookupProfile(name string) (Profile, bool) {
	for _, p := range Profiles {
		if strings.EqualFold(p.Name, name) {
			return p, true
		}
	}
	return Profile{}, false
}

// SameHostFront builds the default posture: SNI = Host = the relay's own
// domain parked behind the CDN.
func SameHostFront(relayHost string) WSFront {
	return WSFront{EdgeAddr: relayHost, EdgeSNI: relayHost, Host: relayHost}
}
