package pkg

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
)

type Formatter struct {
	Domains []*Permutation
}

func NewFormatter(domains []*Permutation) *Formatter {
	return &Formatter{
		Domains: domains,
	}
}

func (f *Formatter) JSON() (string, error) {
	data, err := json.MarshalIndent(f.Domains, "", "    ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func (f *Formatter) CSV() string {
	cols := []string{"fuzzer", "domain"}
	colSet := make(map[string]bool)
	colSet["fuzzer"] = true
	colSet["domain"] = true

	for _, domain := range f.Domains {
		if len(domain.DNSA) > 0 {
			if !colSet["dns_a"] {
				cols = append(cols, "dns_a")
				colSet["dns_a"] = true
			}
		}
		if len(domain.DNSAAAA) > 0 {
			if !colSet["dns_aaaa"] {
				cols = append(cols, "dns_aaaa")
				colSet["dns_aaaa"] = true
			}
		}
		if len(domain.DNSNS) > 0 {
			if !colSet["dns_ns"] {
				cols = append(cols, "dns_ns")
				colSet["dns_ns"] = true
			}
		}
		if len(domain.DNSMX) > 0 {
			if !colSet["dns_mx"] {
				cols = append(cols, "dns_mx")
				colSet["dns_mx"] = true
			}
		}
		if domain.GeoIP != "" {
			if !colSet["geoip"] {
				cols = append(cols, "geoip")
				colSet["geoip"] = true
			}
		}
		if domain.MXSpy {
			if !colSet["mx_spy"] {
				cols = append(cols, "mx_spy")
				colSet["mx_spy"] = true
			}
		}
		if domain.BannerHTTP != "" {
			if !colSet["banner_http"] {
				cols = append(cols, "banner_http")
				colSet["banner_http"] = true
			}
		}
		if domain.BannerSMTP != "" {
			if !colSet["banner_smtp"] {
				cols = append(cols, "banner_smtp")
				colSet["banner_smtp"] = true
			}
		}
		if domain.WhoisRegistrar != "" {
			if !colSet["whois_registrar"] {
				cols = append(cols, "whois_registrar")
				colSet["whois_registrar"] = true
			}
		}
		if domain.WhoisCreated != "" {
			if !colSet["whois_created"] {
				cols = append(cols, "whois_created")
				colSet["whois_created"] = true
			}
		}
		if domain.Ssdeep > 0 {
			if !colSet["ssdeep"] {
				cols = append(cols, "ssdeep")
				colSet["ssdeep"] = true
			}
		}
		if domain.TLSH > 0 {
			if !colSet["tlsh"] {
				cols = append(cols, "tlsh")
				colSet["tlsh"] = true
			}
		}
		if domain.PHash > 0 {
			if !colSet["phash"] {
				cols = append(cols, "phash")
				colSet["phash"] = true
			}
		}
	}

	csv := []string{strings.Join(cols, ",")}

	for _, domain := range f.Domains {
		row := []string{}
		for _, col := range cols {
			val := f.getFieldValue(domain, col)
			if strings.Contains(val, ",") {
				row = append(row, fmt.Sprintf(`"%s"`, val))
			} else {
				row = append(row, val)
			}
		}
		csv = append(csv, strings.Join(row, ","))
	}

	return strings.Join(csv, "\n")
}

func (f *Formatter) getFieldValue(domain *Permutation, field string) string {
	switch field {
	case "fuzzer":
		return domain.Fuzzer
	case "domain":
		return domain.Domain
	case "dns_a":
		return strings.Join(domain.DNSA, ";")
	case "dns_aaaa":
		return strings.Join(domain.DNSAAAA, ";")
	case "dns_ns":
		return strings.Join(domain.DNSNS, ";")
	case "dns_mx":
		return strings.Join(domain.DNSMX, ";")
	case "geoip":
		return domain.GeoIP
	case "mx_spy":
		if domain.MXSpy {
			return "True"
		}
		return ""
	case "banner_http":
		return domain.BannerHTTP
	case "banner_smtp":
		return domain.BannerSMTP
	case "whois_registrar":
		return domain.WhoisRegistrar
	case "whois_created":
		return domain.WhoisCreated
	case "ssdeep":
		if domain.Ssdeep > 0 {
			return fmt.Sprintf("%d", domain.Ssdeep)
		}
		return ""
	case "tlsh":
		if domain.TLSH > 0 {
			return fmt.Sprintf("%d", domain.TLSH)
		}
		return ""
	case "phash":
		if domain.PHash > 0 {
			return fmt.Sprintf("%d", domain.PHash)
		}
		return ""
	}
	return ""
}

func (f *Formatter) List() string {
	lines := []string{}
	for _, domain := range f.Domains {
		lines = append(lines, domain.Domain)
	}
	return strings.Join(lines, "\n")
}

func (f *Formatter) CLI() string {
	domains := f.Domains

	supportsUTF8 := os.Getenv("LANG") != "" && strings.Contains(strings.ToLower(os.Getenv("LANG")), "utf-8")

	if supportsUTF8 {
		for _, domain := range domains {
			decoded, err := IDNADecode(domain.Domain)
			if err == nil {
				domain.Domain = decoded
			}
		}
	}

	wfuz := 0
	wdom := 0
	for _, x := range domains {
		if len(x.Fuzzer) > wfuz {
			wfuz = len(x.Fuzzer)
		}
		if len(x.Domain) > wdom {
			wdom = len(x.Domain)
		}
	}
	wfuz++
	wdom++

	cli := []string{}

	isColorSupported := runtime.GOOS != "windows" && isatty()

	FG_YEL := ""
	FG_CYA := ""
	FG_BLU := ""
	FG_RST := ""

	if isColorSupported {
		FG_YEL = "\x1b[33m"
		FG_CYA = "\x1b[36m"
		FG_BLU = "\x1b[34m"
		FG_RST = "\x1b[39m"
	}

	kv := func(k, v string) string {
		if k != "" {
			return FG_YEL + k + FG_CYA + v + FG_RST
		}
		return FG_CYA + v + FG_RST
	}

	for _, domain := range domains {
		inf := []string{}

		if len(domain.DNSA) > 0 {
			geoStr := ""
			if domain.GeoIP != "" {
				geoStr = kv("/", strings.ReplaceAll(domain.GeoIP, " ", ""))
			}
			inf = append(inf, strings.Join(domain.DNSA, ";")+geoStr)
		}

		if len(domain.DNSAAAA) > 0 {
			inf = append(inf, strings.Join(domain.DNSAAAA, ";"))
		}

		if len(domain.DNSNS) > 0 {
			inf = append(inf, kv("NS:", strings.Join(domain.DNSNS, ";")))
		}

		if len(domain.DNSMX) > 0 {
			mxLabel := "MX:"
			if domain.MXSpy {
				mxLabel = "SPYING-MX:"
			}
			inf = append(inf, kv(mxLabel, strings.Join(domain.DNSMX, ";")))
		}

		if domain.BannerHTTP != "" {
			inf = append(inf, kv("HTTP:", domain.BannerHTTP))
		}

		if domain.BannerSMTP != "" {
			inf = append(inf, kv("SMTP:", domain.BannerSMTP))
		}

		if domain.WhoisRegistrar != "" {
			inf = append(inf, kv("REGISTRAR:", domain.WhoisRegistrar))
		}

		if domain.WhoisCreated != "" {
			inf = append(inf, kv("CREATED:", domain.WhoisCreated))
		}

		if domain.Ssdeep > 0 {
			inf = append(inf, kv("SSDEEP:", fmt.Sprintf("%d%%", domain.Ssdeep)))
		}

		if domain.TLSH > 0 {
			inf = append(inf, kv("TLSH:", fmt.Sprintf("%d%%", domain.TLSH)))
		}

		if domain.PHash > 0 {
			inf = append(inf, kv("PHASH:", fmt.Sprintf("%d%%", domain.PHash)))
		}

		infStr := "-"
		if len(inf) > 0 {
			infStr = strings.Join(inf, " ")
		}

		line := fmt.Sprintf("%s%-*s%s %-*s %s",
			FG_BLU, wfuz, domain.Fuzzer, FG_RST,
			wdom, domain.Domain,
			infStr)

		cli = append(cli, line)
	}

	return strings.Join(cli, "\n")
}

func isatty() bool {
	fileInfo, _ := os.Stdout.Stat()
	return (fileInfo.Mode() & os.ModeCharDevice) != 0
}
