package pkg

import (
	"bufio"
	"net"
	"regexp"
	"strings"
	"time"
)

const (
	WhoisIANA    = "whois.iana.org"
	WhoisTimeout = 2 * time.Second
)

var WhoisTLDServers = map[string]string{
	"com":  "whois.verisign-grs.com",
	"net":  "whois.verisign-grs.com",
	"org":  "whois.pir.org",
	"info": "whois.afilias.net",
	"pl":   "whois.dns.pl",
	"us":   "whois.nic.us",
	"co":   "whois.nic.co",
	"cn":   "whois.cnnic.cn",
	"ru":   "whois.tcinet.ru",
	"in":   "whois.registry.in",
	"eu":   "whois.eu",
	"uk":   "whois.nic.uk",
	"de":   "whois.denic.de",
	"nl":   "whois.domain-registry.nl",
	"br":   "whois.registro.br",
	"jp":   "whois.jprs.jp",
}

type WhoisResult struct {
	Text         string
	Registrar    string
	CreationDate *time.Time
}

type Whois struct {
	whoisTLD map[string]string
}

func NewWhois() *Whois {
	tldMap := make(map[string]string)
	for k, v := range WhoisTLDServers {
		tldMap[k] = v
	}
	return &Whois{
		whoisTLD: tldMap,
	}
}

func (w *Whois) bruteDateTime(s string) *time.Time {
	formats := []string{
		"2006-01-02T15:04:05Z",
		"2006-01-02 15:04:05-0700",
		"2006-01-02 15:04",
		"2006.01.02 15:04",
		"2006.01.02 15:04:05",
		"02.01.2006 15:04:05",
		"Mon Jan 2 2006",
		"02-Jan-2006",
		"2006-01-02",
	}

	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return &t
		}
	}
	return nil
}

func (w *Whois) extract(response string) WhoisResult {
	result := WhoisResult{
		Text: response,
	}

	responseReduced := ""
	scanner := bufio.NewScanner(strings.NewReader(response))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "%") {
			responseReduced += line + "\r\n"
		}
	}

	registrarPattern := regexp.MustCompile(`(?im)[\r\n]registrar[ .]*:\s+(?:name:\s)?([^\r\n]+)`)
	if matches := registrarPattern.FindStringSubmatch(responseReduced); len(matches) > 1 {
		result.Registrar = strings.TrimSpace(matches[1])
	}

	datePattern := regexp.MustCompile(`(?im)[\r\n](?:created(?: on)?|creation date|registered(?: on)?)[ .]*:\s+([^\r\n]+)`)
	if matches := datePattern.FindStringSubmatch(responseReduced); len(matches) > 1 {
		result.CreationDate = w.bruteDateTime(strings.TrimSpace(matches[1]))
	}

	return result
}

func (w *Whois) query(domain string, server string) string {
	if server == "" {
		parts := DomainTLD(domain)
		if serverAddr, ok := w.whoisTLD[parts.TLD]; ok {
			server = serverAddr
		} else {
			server = WhoisIANA
		}
	}

	conn, err := net.DialTimeout("tcp", server+":43", WhoisTimeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(WhoisTimeout))

	_, err = conn.Write([]byte(domain + "\r\n"))
	if err != nil {
		return ""
	}

	response := ""
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		response += string(buf[:n])
	}

	referPattern := regexp.MustCompile(`(?im)refer:\s+([-a-z0-9.]+)`)
	if matches := referPattern.FindStringSubmatch(response); len(matches) > 1 {
		referServer := matches[1]
		if server != WhoisIANA {
			parts := DomainTLD(domain)
			if _, ok := w.whoisTLD[parts.TLD]; !ok {
				w.whoisTLD[parts.TLD] = server
			}
		}
		return w.query(domain, referServer)
	}

	return response
}

func (w *Whois) Whois(domain string) WhoisResult {
	response := w.query(domain, "")
	return w.extract(response)
}
