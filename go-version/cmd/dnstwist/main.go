package main

import (
	"bufio"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"dnstwist/pkg"
)

const banner = `     _           _            _     _
  __| |_ __  ___| |___      _(_)___| |_
 / _` + "`" + ` | '_ \/ __| __\ \ /\ / / / __| __|
| (_| | | | \__ \ |_ \ V  V /| \__ \ |_
 \__,_|_| |_|___/\__| \_/\_/ |_|___/\__| {%s}

`

func main() {
	var (
		domain         string
		all            bool
		banners        bool
		dictionary     string
		format         string
		fuzzers        string
		geoip          bool
		lsh            string
		lshURL         string
		mxcheck        bool
		output         string
		registered     bool
		unregistered   bool
		phash          bool
		phashURL       string
		screenshots    string
		threads        int
		whois          bool
		tld            string
		nameservers    string
		useragent      string
		showVersion    bool
	)

	flag.StringVar(&domain, "domain", "", "Domain name or URL to scan")
	flag.BoolVar(&all, "all", false, "Print all DNS records instead of the first ones")
	flag.BoolVar(&banners, "banners", false, "Determine HTTP and SMTP service banners")
	flag.StringVar(&dictionary, "dictionary", "", "Generate more domains using dictionary FILE")
	flag.StringVar(&format, "format", "cli", "Output format: cli, csv, json, list")
	flag.StringVar(&fuzzers, "fuzzers", "", "Use only selected fuzzing algorithms (separated with commas)")
	flag.BoolVar(&geoip, "geoip", false, "Lookup for GeoIP location")
	flag.StringVar(&lsh, "lsh", "", "Evaluate web page similarity with LSH algorithm: ssdeep, tlsh")
	flag.StringVar(&lshURL, "lsh-url", "", "Override URL to fetch the original web page from")
	flag.BoolVar(&mxcheck, "mxcheck", false, "Check if MX host can be used to intercept emails")
	flag.StringVar(&output, "output", "", "Save output to FILE")
	flag.BoolVar(&registered, "registered", false, "Show only registered domain names")
	flag.BoolVar(&unregistered, "unregistered", false, "Show only unregistered domain names")
	flag.BoolVar(&phash, "phash", false, "Render web pages and evaluate visual similarity")
	flag.StringVar(&phashURL, "phash-url", "", "Override URL to render the original web page from")
	flag.StringVar(&screenshots, "screenshots", "", "Save web page screenshots into DIR")
	flag.IntVar(&threads, "threads", pkg.ThreadCountDefault, "Start specified NUM of threads")
	flag.BoolVar(&whois, "whois", false, "Lookup WHOIS database for creation date and registrar")
	flag.StringVar(&tld, "tld", "", "Swap TLD for the original domain from FILE")
	flag.StringVar(&nameservers, "nameservers", "", "DNS or DoH servers to query (separated with commas)")
	flag.StringVar(&useragent, "useragent", pkg.UserAgentString, "Set User-Agent STRING")
	flag.BoolVar(&showVersion, "version", false, "Show version information")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "dnstwist %s by marcin@ulikowski.pl\n\n", pkg.Version)
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTION]... DOMAIN\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Domain name permutation engine for detecting homograph phishing attacks,\ntyposquatting, fraud and brand impersonation.\n\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if showVersion {
		fmt.Printf("dnstwist %s\n", pkg.Version)
		os.Exit(0)
	}

	if flag.NArg() > 0 {
		domain = flag.Arg(0)
	}

	if domain == "" {
		flag.Usage()
		os.Exit(1)
	}

	if registered && unregistered {
		fmt.Fprintln(os.Stderr, "error: arguments --registered and --unregistered are mutually exclusive")
		os.Exit(1)
	}

	if lsh == "" && lshURL != "" {
		fmt.Fprintln(os.Stderr, "error: argument --lsh-url requires --lsh")
		os.Exit(1)
	}

	if !phash {
		if phashURL != "" {
			fmt.Fprintln(os.Stderr, "error: argument --phash-url requires --phash")
			os.Exit(1)
		}
		if screenshots != "" {
			fmt.Fprintln(os.Stderr, "error: argument --screenshots requires --phash")
			os.Exit(1)
		}
	}

	if format != "cli" && format != "csv" && format != "json" && format != "list" {
		fmt.Fprintln(os.Stderr, "error: invalid output format (choose from cli, csv, json, list)")
		os.Exit(1)
	}

	if threads < 1 {
		fmt.Fprintln(os.Stderr, "error: number of threads must be greater than zero")
		os.Exit(1)
	}

	fuzzerList := []string{}
	if fuzzers != "" {
		fuzzerList = strings.Split(fuzzers, ",")
		for i, f := range fuzzerList {
			fuzzerList[i] = strings.TrimSpace(strings.ToLower(f))
		}
	}

	nameserverList := []string{}
	if nameservers != "" {
		nameserverList = strings.Split(nameservers, ",")
	}

	var dictWords []string
	if dictionary != "" {
		words, err := loadDictionary(dictionary)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: unable to open %s (%s)\n", dictionary, err.Error())
			os.Exit(1)
		}
		dictWords = words
	}

	var tldList []string
	if tld != "" {
		tlds, err := loadTLDList(tld)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: unable to open %s (%s)\n", tld, err.Error())
			os.Exit(1)
		}
		tldList = tlds
	}

	var outFile *os.File
	if output != "" {
		if output == "/dev/null" {
			outFile, _ = os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		} else {
			f, err := os.Create(output)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: unable to open %s (%s)\n", output, err.Error())
				os.Exit(1)
			}
			outFile = f
			defer outFile.Close()
		}
	}

	if geoip {
		if err := pkg.ValidateGeoIPDatabase(); err != nil {
			fmt.Fprintln(os.Stderr, "error: missing geoip2 library or database file (check $GEOLITE2_MMDB environment variable)")
			os.Exit(1)
		}
	}

	urlParser, err := pkg.NewURLParser(domain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid domain name: %s\n", domain)
		os.Exit(1)
	}

	fuzzer := pkg.NewFuzzer(urlParser.Domain, dictWords, tldList)
	fuzzer.Generate(fuzzerList)
	domains := fuzzer.Domains

	if domains.Len() == 0 {
		fmt.Fprintln(os.Stderr, "error: selected fuzzing algorithms do not generate any permutations for provided input domain")
		os.Exit(1)
	}

	if format == "list" {
		formatter := pkg.NewFormatter(domains.ToSortedSlice())
		output := formatter.List()
		if outFile != nil {
			fmt.Fprintln(outFile, output)
		} else {
			fmt.Println(output)
		}
		return
	}

	if outFile == nil && format == "cli" {
		colorCode := rand.Intn(8) + 1
		colorBanner := fmt.Sprintf("\x1b[3%dm\x1b[1m%s\x1b[39m\x1b[0m", colorCode, fmt.Sprintf(banner, pkg.Version))
		fmt.Print(colorBanner)
	}

	var lshInitHash string
	var lshEffectiveURL string
	var lshType pkg.LSHType

	if lsh != "" {
		if lsh == "ssdeep" {
			lshType = pkg.LSHTypeSsdeep
		} else if lsh == "tlsh" {
			lshType = pkg.LSHTypeTLSH
		}

		requestURL := urlParser.FullURI("")
		if lshURL != "" {
			lshParser, err := pkg.NewURLParser(lshURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: invalid domain name: %s\n", lshURL)
				os.Exit(1)
			}
			requestURL = lshParser.FullURI("")
		}

		printCLI(format, fmt.Sprintf("fetching content from: %s ", requestURL))

		opener, err := pkg.NewURLOpener(requestURL, time.Duration(pkg.RequestTimeoutHTTP*float64(time.Second)),
			map[string]string{"User-Agent": useragent}, true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err.Error())
			os.Exit(1)
		}

		printCLI(format, fmt.Sprintf("> %s [%.1f KB]\n", strings.Split(opener.URL, "?")[0], float64(len(opener.Content))/1024.0))

		if lshType == pkg.LSHTypeSsdeep {
			hash, err := pkg.SsdeepHash(opener.NormalizedContent)
			if err == nil {
				lshInitHash = hash
			}
		} else if lshType == pkg.LSHTypeTLSH {
			hash, err := pkg.TLSHHash(opener.NormalizedContent)
			if err == nil {
				lshInitHash = hash
			}
		}

		lshEffectiveURL = strings.Split(opener.URL, "?")[0]

		if lshInitHash == "" || lshInitHash == "TNULL" || lshInitHash == "3::" {
			lsh = ""
		}
	}

	var phashInitHash *pkg.PHash
	if phash {
		requestURL := urlParser.FullURI("")
		if phashURL != "" {
			phashParser, err := pkg.NewURLParser(phashURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: invalid domain name: %s\n", phashURL)
				os.Exit(1)
			}
			requestURL = phashParser.FullURI("")
		}

		printCLI(format, fmt.Sprintf("rendering web page: %s\n", requestURL))

		browser, err := pkg.NewHeadlessBrowser(useragent)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err.Error())
			os.Exit(1)
		}
		defer browser.Stop()

		if err := browser.Get(requestURL); err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err.Error())
			os.Exit(1)
		}

		screenshot, err := browser.Screenshot()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %s\n", err.Error())
			os.Exit(1)
		}

		phashInitHash, _ = pkg.NewPHash(screenshot, 8)
	}

	jobs := make(chan *pkg.Permutation, domains.Len())
	for _, d := range domains.ToSlice() {
		jobs <- d
	}
	close(jobs)

	var wg sync.WaitGroup
	scanners := []*pkg.Scanner{}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Fprintln(os.Stderr, "\nstopping threads...")
		for _, scanner := range scanners {
			scanner.Stop()
		}
	}()

	sid := rand.Int()
	for i := 0; i < threads; i++ {
		scanner := pkg.NewScanner(jobs)
		scanner.ID = sid
		scanner.URL = urlParser
		scanner.OptionExtDNS = true
		scanner.OptionGeoIP = geoip
		scanner.OptionBanners = banners
		scanner.OptionMXCheck = mxcheck
		scanner.Nameservers = nameserverList
		scanner.UserAgent = useragent

		if lsh != "" {
			scanner.OptionLSH = lshType
			scanner.LSHInit = lshInitHash
			scanner.LSHEffectiveURL = lshEffectiveURL
		}

		if phash {
			scanner.OptionPHash = true
			scanner.PHashInit = phashInitHash
			scanner.ScreenshotDir = screenshots
		}

		scanners = append(scanners, scanner)
		wg.Add(1)
		go scanner.Run(&wg)
	}

	printCLI(format, fmt.Sprintf("started %d scanner threads\n", threads))

	startTime := time.Now()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		elapsed := time.Since(startTime).Seconds()
		dlen := domains.Len()
		comp := dlen - len(jobs)

		if comp > 0 {
			rate := int(float64(comp) / elapsed)
			if rate == 0 {
				rate = 1
			}
			eta := len(jobs) / rate
			found := 0
			for _, d := range domains.ToSlice() {
				if d.IsRegistered() {
					found++
				}
			}

			printCLI(format, fmt.Sprintf("\rpermutations: %.2f%% of %d | found: %d | eta: %dm %02ds | speed: %d qps",
				float64(comp)/float64(dlen)*100, dlen, found, eta/60, eta%60, rate))
		}

		if len(jobs) == 0 {
			break
		}

		allStopped := true
		for _, s := range scanners {
			if !s.IsStopped() {
				allStopped = false
				break
			}
		}
		if allStopped {
			break
		}
	}

	printCLI(format, "\n")

	wg.Wait()

	filtered := pkg.FilterPermutations(domains.ToSortedSlice(), registered, unregistered)

	if !all {
		filtered = pkg.CutDNSRecords(filtered)
	}

	if whois {
		total := 0
		for _, d := range filtered {
			if d.IsRegistered() {
				total++
			}
		}

		whoisClient := pkg.NewWhois()
		idx := 0
		for _, d := range filtered {
			if d.IsRegistered() {
				idx++
				printCLI(format, fmt.Sprintf("\rWHOIS: %s (%.2f%%)", d.Domain, float64(idx)/float64(total)*100))

				parts := pkg.DomainTLD(d.Domain)
				whoisDomain := pkg.JoinDomain("", parts.Domain, parts.TLD)
				result := whoisClient.Whois(whoisDomain)

				if result.CreationDate != nil {
					d.WhoisCreated = result.CreationDate.Format("2006-01-02")
				}
				if result.Registrar != "" {
					d.WhoisRegistrar = result.Registrar
				}
			}
		}
		printCLI(format, "\n")
	}

	printCLI(format, "\n")

	formatter := pkg.NewFormatter(filtered)

	var outputStr string
	switch format {
	case "csv":
		outputStr = formatter.CSV()
	case "json":
		outputStr, _ = formatter.JSON()
	case "cli":
		outputStr = formatter.CLI()
	default:
		outputStr = formatter.List()
	}

	if outFile != nil {
		fmt.Fprintln(outFile, outputStr)
	} else {
		fmt.Println(outputStr)
	}
}

func loadDictionary(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	re := regexp.MustCompile(`^(?:(?:xn--)[a-z0-9-]{3,59}|[a-z0-9-]{1,63})$`)
	words := []string{}
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if word != "" && re.MatchString(word) && !seen[word] {
			words = append(words, word)
			seen[word] = true
		}
	}

	return words, scanner.Err()
}

func loadTLDList(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	re := regexp.MustCompile(`^[a-z0-9-]{2,63}(?:\.[a-z0-9-]{2,63})?$`)
	tlds := []string{}
	seen := make(map[string]bool)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		tld := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if tld != "" && re.MatchString(tld) && !seen[tld] {
			tlds = append(tlds, tld)
			seen[tld] = true
		}
	}

	return tlds, scanner.Err()
}

func printCLI(format, text string) {
	if format == "cli" {
		fmt.Fprint(os.Stderr, text)
	}
}
