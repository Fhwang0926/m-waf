package manager

import "testing"

func TestGeoIPTreatsPrivateAndReservedAddressesAsInternal(t *testing.T) {
	resolver := &geoIPResolver{}
	for _, value := range []string{"10.0.0.1", "100.64.0.1", "192.0.2.10", "198.51.100.10", "203.0.113.10", "2001:db8::1", "fe80::1"} {
		if code := resolver.CountryCode(value); code != "--" {
			t.Fatalf("%s must be classified as an internal or reserved address, got %q", value, code)
		}
	}
	if code := resolver.CountryCode("8.8.8.8"); code != "ZZ" {
		t.Fatalf("a public address without an MMDB must remain unknown, got %q", code)
	}
}
