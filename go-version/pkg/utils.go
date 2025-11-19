package pkg

import (
	"strings"

	"golang.org/x/net/idna"
)

type DomainParts struct {
	Subdomain string
	Domain    string
	TLD       string
}

func DomainTLD(domain string) DomainParts {
	commonTLDs := []string{"org", "com", "net", "gov", "edu", "co", "mil", "nom", "ac", "info", "biz", "ne"}

	parts := strings.Split(domain, ".")
	partsLen := len(parts)

	if partsLen < 2 {
		return DomainParts{
			Subdomain: "",
			Domain:    parts[0],
			TLD:       "",
		}
	}

	if partsLen == 2 {
		return DomainParts{
			Subdomain: "",
			Domain:    parts[0],
			TLD:       parts[1],
		}
	}

	if partsLen > 2 {
		secondLevelTLD := parts[partsLen-2]
		isCommonTLD := false
		for _, ctld := range commonTLDs {
			if secondLevelTLD == ctld {
				isCommonTLD = true
				break
			}
		}

		if isCommonTLD {
			if partsLen == 3 {
				return DomainParts{
					Subdomain: "",
					Domain:    parts[0],
					TLD:       parts[1] + "." + parts[2],
				}
			}
			return DomainParts{
				Subdomain: strings.Join(parts[:partsLen-3], "."),
				Domain:    parts[partsLen-3],
				TLD:       parts[partsLen-2] + "." + parts[partsLen-1],
			}
		}

		return DomainParts{
			Subdomain: strings.Join(parts[:partsLen-2], "."),
			Domain:    parts[partsLen-2],
			TLD:       parts[partsLen-1],
		}
	}

	return DomainParts{
		Subdomain: "",
		Domain:    domain,
		TLD:       "",
	}
}

func IDNAEncode(domain string) (string, error) {
	encoded, err := idna.ToASCII(domain)
	if err != nil {
		return "", err
	}
	return encoded, nil
}

func IDNADecode(domain string) (string, error) {
	decoded, err := idna.ToUnicode(domain)
	if err != nil {
		return "", err
	}
	return decoded, nil
}

func JoinDomain(subdomain, domain, tld string) string {
	parts := []string{}
	if subdomain != "" {
		parts = append(parts, subdomain)
	}
	if domain != "" {
		parts = append(parts, domain)
	}
	if tld != "" {
		parts = append(parts, tld)
	}
	return strings.Join(parts, ".")
}

func ValidateDomain(domain string) bool {
	if len(domain) < 1 || len(domain) > 253 {
		return false
	}

	if !ValidFQDNRegex.MatchString(domain) {
		return false
	}

	_, err := IDNADecode(domain)
	return err == nil
}
