package manager

import (
	"net"
	"net/netip"
	"strings"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

var reservedGeoIPNetworks = func() []netip.Prefix {
	values := []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
		"224.0.0.0/4", "240.0.0.0/4", "::/128", "::1/128", "64:ff9b:1::/48", "100::/64", "2001:db8::/32",
		"fc00::/7", "fe80::/10", "ff00::/8",
	}
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		result = append(result, netip.MustParsePrefix(value))
	}
	return result
}()

type geoIPResolver struct {
	database *maxminddb.Reader
}

func (g *geoIPResolver) Close() error {
	if g == nil || g.database == nil {
		return nil
	}
	return g.database.Close()
}

func openGeoIPDatabase(path string) (*geoIPResolver, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return &geoIPResolver{}, nil
	}
	database, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	return &geoIPResolver{database: database}, nil
}

func (g *geoIPResolver) CountryCode(value string) string {
	ip := net.ParseIP(strings.TrimSpace(value))
	if ip == nil {
		return "ZZ"
	}
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return "ZZ"
	}
	address = address.Unmap()
	for _, network := range reservedGeoIPNetworks {
		if network.Contains(address) {
			return "--"
		}
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return "--"
	}
	if g == nil || g.database == nil {
		return "ZZ"
	}
	var record struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
		RegisteredCountry struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"registered_country"`
	}
	if err := g.database.Lookup(ip, &record); err != nil {
		return "ZZ"
	}
	code := strings.ToUpper(strings.TrimSpace(record.Country.ISOCode))
	if code == "" {
		code = strings.ToUpper(strings.TrimSpace(record.RegisteredCountry.ISOCode))
	}
	if len(code) != 2 {
		return "ZZ"
	}
	return code
}
