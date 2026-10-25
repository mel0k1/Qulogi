package route

import "testing"

func TestDecideDomains(t *testing.T) {
	tb := Default()
	cases := []struct {
		addr string
		want Action
	}{
		{"ya.ru:443", ActionDirect},
		{"ya.ru", ActionDirect},
		{"mc.yandex.ru", ActionDirect},
		{"YANDEX.RU:443", ActionDirect},
		{"yandex.ru.", ActionDirect},
		{"www.kinopoisk.ru:443", ActionDirect},
		{"sber.ru", ActionDirect},
		{"api.gosuslugi.ru:443", ActionDirect},
		{"77.88.8.8:53", ActionDirect},
		{"87.240.131.99", ActionDirect},
		{"93.186.225.208:443", ActionDirect},
		{"google.com", ActionProxy},
		{"notyandex.ru", ActionProxy},  // suffix must not match mid-label
		{"badgoogle.com", ActionProxy}, // same
		{"8.8.8.8", ActionProxy},       // unknown IP -> tunnel
		{"1.1.1.1:443", ActionProxy},
	}
	for _, c := range cases {
		if got := tb.Decide(c.addr); got != c.want {
			t.Errorf("Decide(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}

func TestDecideIPv6(t *testing.T) {
	tb := New()
	tb.AddDirect("2a02:6b8::/32")
	if got := tb.Decide("[2a02:6b8:a::1]:443"); got != ActionDirect {
		t.Errorf("IPv6 in range: got %v", got)
	}
	if got := tb.Decide("[2001:db8::1]:443"); got != ActionProxy {
		t.Errorf("IPv6 out of range: got %v", got)
	}
}

func TestMostSpecificWins(t *testing.T) {
	tb := Default()
	tb.AddProxy("camera.yandex.ru")
	if got := tb.Decide("camera.yandex.ru:443"); got != ActionProxy {
		t.Errorf("specific proxy rule ignored: %v", got)
	}
	if got := tb.Decide("mail.yandex.ru:443"); got != ActionDirect {
		t.Errorf("parent rule leaked to sibling: %v", got)
	}

	tb2 := New()
	tb2.AddProxy("yandex.ru") // whole platform through the tunnel
	tb2.AddDirect("mail.yandex.ru")
	if got := tb2.Decide("mail.yandex.ru"); got != ActionDirect {
		t.Errorf("most-specific direct lost: %v", got)
	}
	if got := tb2.Decide("ya.ru"); got != ActionProxy {
		t.Errorf("unrelated domain should be proxied: %v", got)
	}
}

func TestProxyWinsTie(t *testing.T) {
	tb := New()
	tb.AddDirect("example.com")
	tb.AddProxy("example.com")
	if got := tb.Decide("example.com"); got != ActionProxy {
		t.Errorf("proxy should win a tie: %v", got)
	}
}

func TestRuleNormalization(t *testing.T) {
	tb := New()
	tb.AddDirect("https://ya.ru/portal", "*.Yandex.ru", " yandex.ru:443 ", "yandex.ru.", "2a02:6b8::/32")
	cases := map[string]Action{
		"ya.ru":              ActionDirect,
		"www.yandex.ru":      ActionDirect,
		"yandex.ru:443":      ActionDirect,
		"[2a02:6b8:c::1]:80": ActionDirect,
		"notyandex.ru":       ActionProxy,
	}
	for in, want := range cases {
		if got := tb.Decide(in); got != want {
			t.Errorf("Decide(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestParseList(t *testing.T) {
	got := ParseList(" ya.ru, google.com\n\nvk.com ;\n\n")
	if len(got) != 3 || got[0] != "ya.ru" || got[1] != "google.com" || got[2] != "vk.com" {
		t.Errorf("ParseList = %v", got)
	}
	if ParseList("   ") != nil {
		t.Error("ParseList of blanks should be nil")
	}
}
