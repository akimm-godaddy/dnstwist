package pkg

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Scanner struct {
	ID                int
	URL               *URLParser
	Jobs              chan *Permutation
	OptionExtDNS      bool
	OptionGeoIP       bool
	OptionLSH         LSHType
	OptionPHash       bool
	OptionBanners     bool
	OptionMXCheck     bool
	Nameservers       []string
	UserAgent         string
	LSHInit           string
	LSHEffectiveURL   string
	PHashInit         *PHash
	ScreenshotDir     string
	stopMutex         sync.Mutex
	stopped           bool
}

func NewScanner(jobs chan *Permutation) *Scanner {
	return &Scanner{
		Jobs: jobs,
	}
}

func (s *Scanner) Stop() {
	s.stopMutex.Lock()
	defer s.stopMutex.Unlock()
	s.stopped = true
}

func (s *Scanner) IsStopped() bool {
	s.stopMutex.Lock()
	defer s.stopMutex.Unlock()
	return s.stopped
}

func (s *Scanner) sendRecvTCP(host string, port int, data []byte, timeout time.Duration, recvBytes int) string {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	if len(data) > 0 {
		if _, err := conn.Write(data); err != nil {
			return ""
		}
	}

	buf := make([]byte, recvBytes)
	n, err := conn.Read(buf)
	if err != nil {
		return ""
	}

	return string(buf[:n])
}

func (s *Scanner) bannerHTTP(ip, vhost string) string {
	data := fmt.Sprintf("HEAD / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n\r\n", vhost, s.UserAgent)
	response := s.sendRecvTCP(ip, 80, []byte(data), time.Duration(RequestTimeoutHTTP*float64(time.Second)), 1024)

	if response == "" {
		return ""
	}

	lines := strings.Split(response, "\n")
	for _, field := range lines {
		if strings.HasPrefix(strings.ToLower(field), "server: ") {
			return strings.TrimSpace(field[8:])
		}
	}

	return ""
}

func (s *Scanner) bannerSMTP(mx string) string {
	response := s.sendRecvTCP(mx, 25, nil, time.Duration(RequestTimeoutSMTP*float64(time.Second)), 1024)

	if response == "" {
		return ""
	}

	lines := strings.Split(response, "\n")
	if len(lines) > 0 {
		hello := strings.TrimSpace(lines[0])
		if strings.HasPrefix(hello, "220") {
			return strings.TrimSpace(hello[4:])
		}
	}

	return ""
}

func (s *Scanner) mxCheck(mxHost, domainFrom, domainRcpt string) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:25", mxHost), time.Duration(RequestTimeoutSMTP*float64(time.Second)))
	if err != nil {
		return false
	}
	defer conn.Close()

	commands := []string{
		fmt.Sprintf("EHLO %s\r\n", mxHost),
		fmt.Sprintf("MAIL FROM: randombob1986@%s\r\n", domainFrom),
		fmt.Sprintf("RCPT TO: randomalice1986@%s\r\n", domainRcpt),
	}

	buf := make([]byte, 512)
	for _, cmd := range commands {
		n, err := conn.Read(buf)
		if err != nil || n == 0 {
			return false
		}

		if buf[0] != 0x32 {
			return false
		}

		if _, err := conn.Write([]byte(cmd)); err != nil {
			return false
		}
	}

	conn.Close()
	return true
}

func (s *Scanner) Run(wg *sync.WaitGroup) {
	defer wg.Done()

	var resolver *dns.Client
	var dnsConfig *dns.ClientConfig

	if s.OptionExtDNS {
		resolver = &dns.Client{
			Timeout: time.Duration(RequestTimeoutDNS * float64(time.Second)),
		}

		if len(s.Nameservers) > 0 {
			dnsConfig = &dns.ClientConfig{
				Servers: s.Nameservers,
				Port:    "53",
			}
		} else {
			var err error
			dnsConfig, err = dns.ClientConfigFromFile("/etc/resolv.conf")
			if err != nil {
				dnsConfig = &dns.ClientConfig{
					Servers: []string{"8.8.8.8"},
					Port:    "53",
				}
			}
		}
	}

	var geo GeoIP
	if s.OptionGeoIP {
		var err error
		geo, err = NewGeoIP()
		if err != nil {
			s.OptionGeoIP = false
		}
		defer func() {
			if geo != nil {
				geo.Close()
			}
		}()
	}

	var browser *HeadlessBrowser
	if s.OptionPHash {
		var err error
		browser, err = NewHeadlessBrowser(s.UserAgent)
		if err != nil {
			s.OptionPHash = false
		} else {
			defer browser.Stop()
		}
	}

	for !s.IsStopped() {
		select {
		case task, ok := <-s.Jobs:
			if !ok {
				return
			}

			domain := task.Domain
			dnsA := false
			dnsAAAA := false

			if s.OptionExtDNS {
				nxdomain := false
				dnsNS := false
				dnsMX := false

				nsRecords := s.queryDNS(resolver, dnsConfig, domain, dns.TypeNS)
				if nsRecords != nil {
					if len(nsRecords) > 0 && nsRecords[0] == "!ServFail" {
						task.DNSNS = nsRecords
					} else if len(nsRecords) > 0 && nsRecords[0] == "!NXDOMAIN" {
						nxdomain = true
					} else {
						task.DNSNS = nsRecords
						dnsNS = true
					}
				}

				if !nxdomain {
					aRecords := s.queryDNS(resolver, dnsConfig, domain, dns.TypeA)
					if aRecords != nil && len(aRecords) > 0 {
						if aRecords[0] == "!ServFail" {
							task.DNSA = aRecords
						} else {
							task.DNSA = aRecords
							dnsA = true
						}
					}

					aaaaRecords := s.queryDNS(resolver, dnsConfig, domain, dns.TypeAAAA)
					if aaaaRecords != nil && len(aaaaRecords) > 0 {
						if aaaaRecords[0] == "!ServFail" {
							task.DNSAAAA = aaaaRecords
						} else {
							task.DNSAAAA = aaaaRecords
							dnsAAAA = true
						}
					}
				}

				if !nxdomain && dnsNS {
					mxRecords := s.queryDNS(resolver, dnsConfig, domain, dns.TypeMX)
					if mxRecords != nil && len(mxRecords) > 0 {
						if mxRecords[0] == "!ServFail" {
							task.DNSMX = mxRecords
						} else {
							task.DNSMX = mxRecords
							dnsMX = true
						}
					}
				}

				if s.OptionMXCheck && dnsMX && domain != s.URL.Domain {
					if s.mxCheck(task.DNSMX[0], s.URL.Domain, domain) {
						task.MXSpy = true
					}
				}
			} else {
				addrs, err := net.LookupIP(domain)
				if err == nil {
					ipv4List := []string{}
					ipv6List := []string{}

					for _, addr := range addrs {
						if ipv4 := addr.To4(); ipv4 != nil {
							ipv4List = append(ipv4List, addr.String())
						} else {
							ipv6List = append(ipv6List, addr.String())
						}
					}

					if len(ipv4List) > 0 {
						task.DNSA = ipv4List
						dnsA = true
					}
					if len(ipv6List) > 0 {
						task.DNSAAAA = ipv6List
						dnsAAAA = true
					}
				}
			}

			if s.OptionGeoIP && dnsA && geo != nil {
				country, err := geo.CountryByAddr(task.DNSA[0])
				if err == nil && country != "" {
					task.GeoIP = ExtractCountry(country)
				}
			}

			if s.OptionBanners {
				if dnsA {
					banner := s.bannerHTTP(task.DNSA[0], domain)
					if banner != "" {
						task.BannerHTTP = banner
					}
				}
				if len(task.DNSMX) > 0 {
					banner := s.bannerSMTP(task.DNSMX[0])
					if banner != "" {
						task.BannerSMTP = banner
					}
				}
			}

			if (s.OptionPHash || s.ScreenshotDir != "") && (dnsA || dnsAAAA) && browser != nil {
				url := s.URL.FullURI(domain)
				if err := browser.Get(url); err == nil {
					screenshot, err := browser.Screenshot()
					if err == nil {
						if s.OptionPHash && s.PHashInit != nil {
							phash, err := NewPHash(screenshot, 8)
							if err == nil {
								task.PHash = s.PHashInit.Compare(phash)
							}
						}
						if s.ScreenshotDir != "" {
							filename := fmt.Sprintf("%s/%08x_%s.png", s.ScreenshotDir, s.ID, domain)
							_ = saveFile(filename, screenshot)
						}
					}
				}
			}

			if s.OptionLSH != "" && (dnsA || dnsAAAA) {
				url := s.URL.FullURI(domain)
				opener, err := NewURLOpener(url, time.Duration(RequestTimeoutHTTP*float64(time.Second)),
					map[string]string{"User-Agent": s.UserAgent}, false)
				if err == nil {
					urlWithoutQuery := strings.Split(opener.URL, "?")[0]
					if urlWithoutQuery != s.LSHEffectiveURL {
						if s.OptionLSH == LSHTypeSsdeep {
							lshCurr, err := SsdeepHash(opener.NormalizedContent)
							if err == nil && IsValidSsdeepHash(lshCurr) {
								score, err := SsdeepCompare(s.LSHInit, lshCurr)
								if err == nil {
									task.Ssdeep = score
								}
							}
						} else if s.OptionLSH == LSHTypeTLSH {
							lshCurr, err := TLSHHash(opener.NormalizedContent)
							if err == nil && IsValidTLSHHash(lshCurr) {
								score, err := TLSHCompare(s.LSHInit, lshCurr)
								if err == nil {
									task.TLSH = score
								}
							}
						}
					}
				}
			}

		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func (s *Scanner) queryDNS(resolver *dns.Client, config *dns.ClientConfig, domain string, qtype uint16) []string {
	if len(config.Servers) == 0 {
		return nil
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true

	var r *dns.Msg
	var err error

	for _, server := range config.Servers {
		serverAddr := net.JoinHostPort(server, config.Port)
		r, _, err = resolver.Exchange(m, serverAddr)
		if err == nil {
			break
		}
	}

	if err != nil {
		return []string{"!ServFail"}
	}

	if r.Rcode == dns.RcodeNameError {
		return []string{"!NXDOMAIN"}
	}

	if r.Rcode == dns.RcodeServerFailure {
		return []string{"!ServFail"}
	}

	results := []string{}
	for _, ans := range r.Answer {
		switch qtype {
		case dns.TypeA:
			if a, ok := ans.(*dns.A); ok {
				results = append(results, a.A.String())
			}
		case dns.TypeAAAA:
			if aaaa, ok := ans.(*dns.AAAA); ok {
				results = append(results, aaaa.AAAA.String())
			}
		case dns.TypeNS:
			if ns, ok := ans.(*dns.NS); ok {
				results = append(results, strings.TrimSuffix(ns.Ns, "."))
			}
		case dns.TypeMX:
			if mx, ok := ans.(*dns.MX); ok {
				results = append(results, strings.TrimSuffix(mx.Mx, "."))
			}
		}
	}

	sort.Strings(results)
	return results
}

func saveFile(filename string, data []byte) error {
	return writeFile(filename, data, 0644)
}

func writeFile(filename string, data []byte, perm int) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.Write(data)
	return err
}
