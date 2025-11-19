package pkg

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"io"
	"net/http"
	"regexp"
	"time"
)

type URLOpener struct {
	Headers           http.Header
	Code              int
	Reason            string
	URL               string
	Content           []byte
	NormalizedContent []byte
}

func NewURLOpener(urlStr string, timeout time.Duration, headers map[string]string, verify bool) (*URLOpener, error) {
	httpHeaders := map[string]string{
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9",
		"Accept-Encoding": "gzip,identity",
		"Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
	}

	for k, v := range headers {
		httpHeaders[k] = v
	}

	transport := &http.Transport{}
	if !verify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil
		},
	}

	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil, err
	}

	for k, v := range httpHeaders {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if len(body) >= 3 && body[0] == 0x1f && body[1] == 0x8b && body[2] == 0x08 {
		gzReader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		defer gzReader.Close()

		body, err = io.ReadAll(gzReader)
		if err != nil {
			return nil, err
		}
	}

	opener := &URLOpener{
		Headers: resp.Header,
		Code:    resp.StatusCode,
		Reason:  resp.Status,
		URL:     resp.Request.URL.String(),
		Content: body,
	}

	if len(body) > 64 && len(body) < 1024 {
		metaURLRegex := regexp.MustCompile(`(?i)<meta[^>]*?url=(https?://[\w.,?!:;/*#@$&+=[\]()%~-]*?)"`)
		matches := metaURLRegex.FindStringSubmatch(string(body))
		if len(matches) > 1 {
			return NewURLOpener(matches[1], timeout, headers, verify)
		}
	}

	opener.NormalizedContent = opener.normalize()

	return opener, nil
}

func (u *URLOpener) normalize() []byte {
	content := bytes.Join(bytes.Fields(u.Content), []byte(" "))

	mappings := map[string]string{
		`(?i)(action|src|href)=".+"`: `$1=""`,
		`(?i)url\(.+\)`:               `url()`,
	}

	for pattern, repl := range mappings {
		re := regexp.MustCompile(pattern)
		content = re.ReplaceAll(content, []byte(repl))
	}

	return content
}
