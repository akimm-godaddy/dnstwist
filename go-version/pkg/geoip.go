package pkg

import (
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/oschwald/geoip2-golang"
)

type GeoIP interface {
	CountryByAddr(ipaddr string) (string, error)
	Close() error
}

type GeoIP2Reader struct {
	reader *geoip2.Reader
}

func NewGeoIP() (GeoIP, error) {
	geolite2Path := os.Getenv("GEOLITE2_MMDB")
	if geolite2Path == "" {
		execPath, err := os.Executable()
		if err != nil {
			geolite2Path = "GeoLite2-Country.mmdb"
		} else {
			geolite2Path = filepath.Join(filepath.Dir(execPath), "GeoLite2-Country.mmdb")
		}
	}

	reader, err := geoip2.Open(geolite2Path)
	if err != nil {
		return nil, err
	}

	return &GeoIP2Reader{
		reader: reader,
	}, nil
}

func (g *GeoIP2Reader) CountryByAddr(ipaddr string) (string, error) {
	ip := net.ParseIP(ipaddr)
	if ip == nil {
		return "", nil
	}

	record, err := g.reader.Country(ip)
	if err != nil {
		return "", err
	}

	return record.Country.Names["en"], nil
}

func (g *GeoIP2Reader) Close() error {
	if g.reader != nil {
		return g.reader.Close()
	}
	return nil
}

func ValidateGeoIPDatabase() error {
	geolite2Path := os.Getenv("GEOLITE2_MMDB")
	if geolite2Path == "" {
		execPath, err := os.Executable()
		if err != nil {
			geolite2Path = "GeoLite2-Country.mmdb"
		} else {
			geolite2Path = filepath.Join(filepath.Dir(execPath), "GeoLite2-Country.mmdb")
		}
	}

	reader, err := geoip2.Open(geolite2Path)
	if err != nil {
		return err
	}
	defer reader.Close()

	testIP := net.ParseIP("8.8.8.8")
	_, err = reader.Country(testIP)
	if err != nil {
		return err
	}

	return nil
}

func ExtractCountry(country string) string {
	if country == "" {
		return ""
	}
	parts := strings.Split(country, ",")
	return strings.TrimSpace(parts[0])
}
