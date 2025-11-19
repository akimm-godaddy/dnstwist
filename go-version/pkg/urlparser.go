package pkg

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

type URLParser struct {
	Scheme   string
	Domain   string
	Username string
	Password string
	Port     int
	Path     string
	Query    string
	Fragment string
}

func NewURLParser(urlStr string) (*URLParser, error) {
	if urlStr == "" {
		return nil, errors.New("argument has to be non-empty string")
	}

	if !strings.Contains(urlStr, "://") {
		urlStr = "//" + urlStr
	}

	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, errors.New("invalid URL")
	}

	scheme := parsedURL.Scheme
	if scheme == "" {
		scheme = "http"
	}

	scheme = strings.ToLower(scheme)
	if scheme != "http" && scheme != "https" {
		return nil, errors.New("invalid scheme")
	}

	hostname := parsedURL.Hostname()
	if hostname == "" {
		return nil, errors.New("invalid domain name")
	}

	hostname = strings.ToLower(hostname)

	encodedDomain, err := IDNAEncode(hostname)
	if err != nil {
		return nil, errors.New("invalid domain name")
	}

	if !ValidateDomain(encodedDomain) {
		return nil, errors.New("invalid domain name")
	}

	parser := &URLParser{
		Scheme:   scheme,
		Domain:   encodedDomain,
		Path:     parsedURL.Path,
		Query:    parsedURL.RawQuery,
		Fragment: parsedURL.Fragment,
	}

	if parsedURL.User != nil {
		parser.Username = parsedURL.User.Username()
		if pwd, set := parsedURL.User.Password(); set {
			parser.Password = pwd
		}
	}

	if parsedURL.Port() != "" {
		var port int
		if _, err := fmt.Sscanf(parsedURL.Port(), "%d", &port); err == nil {
			parser.Port = port
		}
	}

	return parser, nil
}

func (p *URLParser) FullURI(domain string) string {
	if domain == "" {
		domain = p.Domain
	}

	uri := fmt.Sprintf("%s://", p.Scheme)

	if p.Username != "" {
		uri += p.Username
		if p.Password != "" {
			uri += fmt.Sprintf(":%s", p.Password)
		}
		uri += "@"
	}

	uri += domain

	if p.Port > 0 {
		uri += fmt.Sprintf(":%d", p.Port)
	}

	if p.Path != "" {
		uri += p.Path
	}

	if p.Query != "" {
		uri += fmt.Sprintf("?%s", p.Query)
	}

	if p.Fragment != "" {
		uri += fmt.Sprintf("#%s", p.Fragment)
	}

	return uri
}
