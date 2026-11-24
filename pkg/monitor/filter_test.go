package monitor

import (
	"testing"
	"time"
)

func fm(rule, kind, domain string) *Match { return &Match{RuleID: rule, Kind: kind, Domain: domain} }

func TestDedupeWithinTheWindow(t *testing.T) {
	f := NewFilter(24*time.Hour, 500, 0)
	now := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	f.now = func() time.Time { return now }
	if ok, _ := f.Accept(fm("r", "keyword", "paypal-login.xyz")); !ok {
		t.Fatal("first time")
	}
	if ok, _ := f.Accept(fm("r", "keyword", "paypal-login.xyz")); ok {
		t.Fatal("the same hit again within 24 h")
	}
	if ok, _ := f.Accept(fm("r", "lookalike", "paypal-login.xyz")); !ok {
		t.Fatal("another kind is another hit")
	}
	if ok, _ := f.Accept(fm("other", "keyword", "paypal-login.xyz")); !ok {
		t.Fatal("another rule is another hit")
	}
	now = now.Add(23 * time.Hour)
	if ok, _ := f.Accept(fm("r", "keyword", "paypal-login.xyz")); ok {
		t.Fatal("23 hours later is still inside the window")
	}
	now = now.Add(2 * time.Hour) // 25 h after the first report; the window does not slide on suppressed repeats
	if ok, _ := f.Accept(fm("r", "keyword", "paypal-login.xyz")); !ok {
		t.Fatal("after the window it is reported again")
	}
}

func TestDailyCapSilencesAfterOneNoisyEvent(t *testing.T) {
	f := NewFilter(24*time.Hour, 3, 0)
	now := time.Date(2026, 11, 24, 23, 0, 0, 0, time.UTC)
	f.now = func() time.Time { return now }
	var meta int
	accepted := 0
	for i := 0; i < 10; i++ {
		ok, m := f.Accept(fm("noisy", "keyword", string(rune('a'+i))+".example"))
		if ok {
			accepted++
		}
		if m != nil {
			meta++
			if m.Kind != KindRuleNoisy || m.RuleID != "noisy" || len(m.Reasons) == 0 {
				t.Fatalf("%+v", m)
			}
		}
	}
	if accepted != 3 || meta != 1 {
		t.Fatalf("accepted %d, noisy events %d", accepted, meta)
	}
	if ok, _ := f.Accept(fm("quiet", "keyword", "x.example")); !ok {
		t.Fatal("another rule is not affected")
	}
	now = now.Add(2 * time.Hour) // after midnight UTC
	if ok, _ := f.Accept(fm("noisy", "keyword", "new.example")); !ok {
		t.Fatal("a new UTC day starts afresh")
	}
}

func TestTheMemoryIsBounded(t *testing.T) {
	f := NewFilter(24*time.Hour, 1_000_000, 100)
	for i := 0; i < 1000; i++ {
		f.Accept(fm("r", "keyword", "host"+itoa(i)+".example"))
	}
	if f.Size() > 100 {
		t.Fatalf("%d keys remembered, limit 100", f.Size())
	}
	// the newest are still remembered, the oldest were forgotten (and may be reported again)
	if ok, _ := f.Accept(fm("r", "keyword", "host999.example")); ok {
		t.Error("a recent key was forgotten")
	}
	if ok, _ := f.Accept(fm("r", "keyword", "host0.example")); !ok {
		t.Error("the oldest key should have been evicted")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}
