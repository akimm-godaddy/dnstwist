package pkg

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/chromedp/chromedp"
)

type HeadlessBrowser struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func NewHeadlessBrowser(userAgent string) (*HeadlessBrowser, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("disable-dev-shm-usage", true),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("headless", true),
		chromedp.Flag("incognito", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("disable-extensions", true),
		chromedp.Flag("disk-cache-size", 0),
		chromedp.Flag("aggressive-cache-discard", true),
		chromedp.Flag("disable-notifications", true),
		chromedp.Flag("disable-remote-fonts", true),
		chromedp.Flag("disable-sync", true),
		chromedp.WindowSize(1366, 768),
		chromedp.Flag("hide-scrollbars", true),
		chromedp.Flag("disable-audio-output", true),
		chromedp.Flag("dns-prefetch-disable", true),
		chromedp.Flag("no-default-browser-check", true),
		chromedp.Flag("disable-background-networking", true),
		chromedp.Flag("enable-features", "NetworkService,NetworkServiceInProcess"),
		chromedp.Flag("disable-background-timer-throttling", true),
		chromedp.Flag("disable-backgrounding-occluded-windows", true),
		chromedp.Flag("disable-breakpad", true),
		chromedp.Flag("disable-client-side-phishing-detection", true),
		chromedp.Flag("disable-component-extensions-with-background-pages", true),
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("disable-features", "TranslateUI"),
		chromedp.Flag("disable-hang-monitor", true),
		chromedp.Flag("disable-ipc-flooding-protection", true),
		chromedp.Flag("disable-prompt-on-repost", true),
		chromedp.Flag("disable-renderer-backgrounding", true),
		chromedp.Flag("force-color-profile", "srgb"),
		chromedp.Flag("metrics-recording-only", true),
		chromedp.Flag("no-first-run", true),
		chromedp.Flag("password-store", "basic"),
		chromedp.Flag("use-mock-keychain", true),
		chromedp.Flag("disable-blink-features", "AutomationControlled"),
	)

	httpProxy := os.Getenv("http_proxy")
	httpsProxy := os.Getenv("https_proxy")
	if httpProxy == "" {
		httpProxy = os.Getenv("HTTP_PROXY")
	}
	if httpsProxy == "" {
		httpsProxy = os.Getenv("HTTPS_PROXY")
	}

	if httpProxy != "" || httpsProxy != "" {
		proxyServers := []string{}
		if httpProxy != "" {
			if u, err := url.Parse(httpProxy); err == nil {
				proxyServers = append(proxyServers, fmt.Sprintf("http=%s", u.Host))
			}
		}
		if httpsProxy != "" {
			if u, err := url.Parse(httpsProxy); err == nil {
				proxyServers = append(proxyServers, fmt.Sprintf("https=%s", u.Host))
			}
		}
		if len(proxyServers) > 0 {
			proxyString := ""
			for i, ps := range proxyServers {
				if i > 0 {
					proxyString += ";"
				}
				proxyString += ps
			}
			opts = append(opts, chromedp.ProxyServer(proxyString))
		}
	}

	if userAgent != "" {
		opts = append(opts, chromedp.UserAgent(userAgent))
	}

	allocCtx, _ := chromedp.NewExecAllocator(context.Background(), opts...)
	ctx, cancel := chromedp.NewContext(allocCtx)

	return &HeadlessBrowser{
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

func (b *HeadlessBrowser) Get(url string) error {
	timeout := time.Duration(WebdriverPageloadTimeout * float64(time.Second))
	ctx, cancel := context.WithTimeout(b.ctx, timeout)
	defer cancel()

	return chromedp.Run(ctx,
		chromedp.Navigate(url),
	)
}

func (b *HeadlessBrowser) Screenshot() ([]byte, error) {
	var buf []byte
	if err := chromedp.Run(b.ctx,
		chromedp.CaptureScreenshot(&buf),
	); err != nil {
		return nil, err
	}
	return buf, nil
}

func (b *HeadlessBrowser) Stop() {
	if b.cancel != nil {
		b.cancel()
	}
}
