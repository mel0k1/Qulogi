package transport

import (
        "crypto/rand"
        "encoding/binary"
)

// TLS extension types (subset used by the generated ClientHello).
const (
        extServerName            = 0x0000
        extStatusRequest         = 0x0005
        extSupportedGroups       = 0x000a
        extECPointFormats        = 0x000b
        extSignatureAlgorithms   = 0x000d
        extSCT                   = 0x0012
        extExtendedMasterSecret  = 0x0017
        extSessionTicket         = 0x0023
        extKeyShare              = 0x0033
        extSupportedVersions     = 0x002b
        extPSKExchangeModes      = 0x002d
        extCompressCertificate   = 0x001b
        extRenegotiationInfo     = 0xff01
        extGREASE                = 0x0a0a
)

// chromeCipherSuites mirrors a modern browser suite list (TLS 1.3 first,
// then strong ECDHE suites) so the fingerprint does not stand out.
var chromeCipherSuites = []uint16{
        0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8,
        0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035, 0x000a,
}

// chromeGroups is the supported_groups list: x25519, secp256r1, secp384r1
// plus a GREASE tail.
var chromeGroups = []uint16{0x001d, 0x0017, 0x0018, 0x0a0a}

// chromeSignAlgs mirrors browser signature_algorithms.
var chromeSignAlgs = []uint16{
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
}

func randBytes(n int) []byte {
        b := make([]byte, n)
        _, _ = rand.Read(b)
        return b
}

func putU16(dst []byte, v uint16) {
        binary.BigEndian.PutUint16(dst, v)
}

func appendExt(dst []byte, typ uint16, body []byte) []byte {
        var hdr [4]byte
        putU16(hdr[:2], typ)
        putU16(hdr[2:], uint16(len(body)))
        dst = append(dst, hdr[:]...)
        return append(dst, body...)
}

func appendSNIExtension(dst []byte, sni string) []byte {
        body := make([]byte, 0, len(sni)+5)
        var list [2]byte
        putU16(list[:], uint16(len(sni)+3))
        body = append(body, list[:]...)
        body = append(body, 0) // host_name
        var nl [2]byte
        putU16(nl[:], uint16(len(sni)))
        body = append(body, nl[:]...)
        body = append(body, sni...)
        return appendExt(dst, extServerName, body)
}

func appendKeyShare(dst []byte) []byte {
        // x25519 key share: 32 random bytes. Random is indistinguishable from a
        // real scalar-encoded point for x25519 purposes.
        share := randBytes(32)
        body := make([]byte, 0, 2+2+2+32)
        var group [2]byte
        putU16(group[:], 0x001d)
        body = append(body, group[:]...)
        var ln [2]byte
        putU16(ln[:], uint16(len(share)))
        body = append(body, ln[:]...)
        body = append(body, share...)
        return appendExt(dst, extKeyShare, body)
}

func u16ListExt(typ uint16, values []uint16) []byte {
        body := make([]byte, 2, 2+2*len(values))
        putU16(body, uint16(2*len(values)))
        for _, v := range values {
                var b [2]byte
                putU16(b[:], v)
                body = append(body, b[:]...)
        }
        return appendExt(nil, typ, body)
}

// BuildClientHello returns full TLS record bytes (record header included)
// carrying a browser-like ClientHello that advertises the given SNI.
// The result length is padded to the common 517-byte shape of Chrome handshakes.
func BuildClientHello(sni string) []byte {
        if sni == "" {
                sni = "vkvideo.ru"
        }

        // Handshake body.
        body := make([]byte, 0, 512)
        body = append(body, 0x03, 0x03) // legacy_version TLS 1.2
        body = append(body, randBytes(32)...)
        body = append(body, 32) // session_id len (TLS 1.3 compat shape)
        body = append(body, randBytes(32)...)

        cs := make([]byte, 2, 2+2*len(chromeCipherSuites))
        putU16(cs, uint16(len(chromeCipherSuites)*2))
        for _, v := range chromeCipherSuites {
                var b [2]byte
                putU16(b[:], v)
                cs = append(cs, b[:]...)
        }
        body = append(body, cs[:]...)
        body = append(body, 1, 0) // compression: null

        exts := make([]byte, 0, 400)
        var grease [2]byte
        putU16(grease[:], extGREASE)
        exts = append(exts, grease[:]...)
        exts = append(exts, 0, 0) // GREASE, empty

        exts = appendSNIExtension(exts, sni)
        exts = appendExt(exts, extExtendedMasterSecret, nil)
        exts = appendExt(exts, extRenegotiationInfo, []byte{0})
        exts = append(exts, u16ListExt(extSupportedGroups, chromeGroups)...)
        exts = appendExt(exts, extECPointFormats, []byte{1, 0})
        exts = appendExt(exts, extSessionTicket, nil)
        exts = append(exts, u16ListExt(extSignatureAlgorithms, chromeSignAlgs)...)
        exts = appendExt(exts, extStatusRequest, []byte{0})
        exts = appendExt(exts, extSCT, nil)
        exts = appendKeyShare(exts)
        exts = appendExt(exts, extPSKExchangeModes, []byte{1})

        var sv [8]byte
        putU16(sv[:], 6)       // list length: three versions
        putU16(sv[2:], 0x1a1a) // GREASE
        putU16(sv[4:], 0x0304) // TLS 1.3
        putU16(sv[6:], 0x0303) // TLS 1.2
        exts = appendExt(exts, extSupportedVersions, sv[:])

        exts = appendExt(exts, extCompressCertificate, []byte{2, 0x02, 0x01}) // zstd, brotli

        var eh [2]byte
        putU16(eh[:], uint16(len(exts)))
        body = append(body, eh[:]...)
        body = append(body, exts...)

        // Pad to the familiar ~517 byte handshake length using the padding ext.
        const target = 517
        if hsLen := 4 + len(body); hsLen < target {
                if pad := target - hsLen - 4; pad >= 4 {
                        body = appendExt(body, 0x0015, make([]byte, pad))
                }
        }

        hs := make([]byte, 0, len(body)+4)
        hs = append(hs, 0x01)
        hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
        hs = append(hs, body...)

        rec := make([]byte, 0, len(hs)+recHeaderSize)
        rec = append(rec, recHandshake, 0x03, 0x01)
        var rl [2]byte
        putU16(rl[:], uint16(len(hs)))
        rec = append(rec, rl[:]...)
        rec = append(rec, hs...)
        return rec
}

// fakeServerFlight builds the server-side camouflage flight: a ServerHello
// and a ChangeCipherSpec record. The session id is randomised so repeated
// connections do not look byte-identical.
func fakeServerFlight() [][]byte {
        body := make([]byte, 0, 92)
        body = append(body, 0x03, 0x03)
        body = append(body, randBytes(32)...) // server random
        body = append(body, 32)
        body = append(body, randBytes(32)...) // session id (echo-shaped)
        body = append(body, 0x13, 0x01)       // cipher: TLS_AES_128_GCM_SHA256
        body = append(body, 0)                // compression null
        var exts [2]byte
        putU16(exts[:], 0)
        body = append(body, exts[:]...)

        hs := make([]byte, 0, len(body)+4)
        hs = append(hs, 0x02)
        hs = append(hs, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
        hs = append(hs, body...)

        sh := make([]byte, 0, len(hs)+recHeaderSize)
        sh = append(sh, recHandshake, 0x03, 0x03)
        var rl [2]byte
        putU16(rl[:], uint16(len(hs)))
        sh = append(sh, rl[:]...)
        sh = append(sh, hs...)

        ccs := []byte{recChangeCipherSpec, 0x03, 0x03, 0x00, 0x01, 0x01}
        return [][]byte{sh, ccs}
}
