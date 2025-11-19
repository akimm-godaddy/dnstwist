package pkg

import (
	"strings"
)

type Fuzzer struct {
	Subdomain     string
	Domain        string
	TLD           string
	Dictionary    []string
	TLDDictionary []string
	Domains       *PermutationSet
}

func NewFuzzer(domain string, dictionary, tldDictionary []string) *Fuzzer {
	parts := DomainTLD(domain)

	decodedDomain, err := IDNADecode(parts.Domain)
	if err != nil {
		decodedDomain = parts.Domain
	}

	return &Fuzzer{
		Subdomain:     parts.Subdomain,
		Domain:        decodedDomain,
		TLD:           parts.TLD,
		Dictionary:    dictionary,
		TLDDictionary: tldDictionary,
		Domains:       NewPermutationSet(),
	}
}

func (f *Fuzzer) bitsquatting() []string {
	masks := []byte{1, 2, 4, 8, 16, 32, 64, 128}
	chars := "abcdefghijklmnopqrstuvwxyz0123456789-"
	charSet := make(map[byte]bool)
	for i := 0; i < len(chars); i++ {
		charSet[chars[i]] = true
	}

	results := []string{}
	for i := 0; i < len(f.Domain); i++ {
		c := f.Domain[i]
		for _, mask := range masks {
			b := c ^ mask
			if charSet[b] {
				results = append(results, f.Domain[:i]+string(b)+f.Domain[i+1:])
			}
		}
	}
	return results
}

func (f *Fuzzer) cyrillic() []string {
	cdomain := f.Domain
	for latin, cyrillic := range LatinToCyrillic {
		cdomain = strings.ReplaceAll(cdomain, latin, cyrillic)
	}

	for i := 0; i < len(cdomain); i++ {
		if i < len(f.Domain) && cdomain[i] == f.Domain[i] {
			return []string{}
		}
	}
	return []string{cdomain}
}

func (f *Fuzzer) homoglyph() []string {
	glyphs := make(map[string][]string)

	for k, v := range GlyphsASCII {
		glyphs[k] = v
	}

	tldGlyphs, hasTLD := GlyphsIDNByTLD[f.TLD]
	var unicodeGlyphs map[string][]string
	if hasTLD && len(tldGlyphs) > 0 {
		unicodeGlyphs = tldGlyphs
	} else {
		unicodeGlyphs = GlyphsUnicode
	}

	for k, v := range unicodeGlyphs {
		if existing, ok := glyphs[k]; ok {
			combined := append([]string{}, existing...)
			combined = append(combined, v...)
			glyphs[k] = combined
		} else {
			glyphs[k] = v
		}
	}

	mix := func(domain string) []string {
		results := []string{}
		for i := 0; i < len(domain); i++ {
			c := string(domain[i])
			if g, ok := glyphs[c]; ok {
				for _, glyph := range g {
					results = append(results, domain[:i]+glyph+domain[i+1:])
				}
			}
		}

		for i := 0; i < len(domain)-1; i++ {
			win := domain[i : i+2]
			checkChars := []string{string(domain[i]), string(domain[i+1]), win}
			for _, c := range checkChars {
				if g, ok := glyphs[c]; ok {
					for _, glyph := range g {
						results = append(results, domain[:i]+strings.Replace(win, c, glyph, 1)+domain[i+2:])
					}
				}
			}
		}
		return results
	}

	result1 := mix(f.Domain)
	result2 := []string{}
	for _, r := range result1 {
		result2 = append(result2, mix(r)...)
	}

	resultSet := make(map[string]bool)
	for _, r := range result1 {
		resultSet[r] = true
	}
	for _, r := range result2 {
		resultSet[r] = true
	}

	results := []string{}
	for r := range resultSet {
		results = append(results, r)
	}
	return results
}

func (f *Fuzzer) hyphenation() []string {
	results := []string{}
	for i := 1; i < len(f.Domain); i++ {
		results = append(results, f.Domain[:i]+"-"+f.Domain[i:])
	}
	return results
}

func (f *Fuzzer) insertion() []string {
	resultSet := make(map[string]bool)

	for i := 0; i < len(f.Domain)-1; i++ {
		prefix := f.Domain[:i]
		origC := string(f.Domain[i])
		suffix := f.Domain[i+1:]

		for _, keyboard := range Keyboards {
			if adjacent, ok := keyboard[origC]; ok {
				for _, c := range adjacent {
					resultSet[prefix+string(c)+origC+suffix] = true
					resultSet[prefix+origC+string(c)+suffix] = true
				}
			}
		}
	}

	results := []string{}
	for r := range resultSet {
		results = append(results, r)
	}
	return results
}

func (f *Fuzzer) omission() []string {
	results := []string{}
	for i := 0; i < len(f.Domain); i++ {
		results = append(results, f.Domain[:i]+f.Domain[i+1:])
	}
	return results
}

func (f *Fuzzer) repetition() []string {
	results := []string{}
	for i := 0; i < len(f.Domain); i++ {
		c := string(f.Domain[i])
		results = append(results, f.Domain[:i]+c+f.Domain[i:])
	}
	return results
}

func (f *Fuzzer) replacement() []string {
	results := []string{}
	for i := 0; i < len(f.Domain); i++ {
		pre := f.Domain[:i]
		suf := f.Domain[i+1:]
		c := string(f.Domain[i])

		for _, layout := range Keyboards {
			if replacements, ok := layout[c]; ok {
				for _, r := range replacements {
					results = append(results, pre+string(r)+suf)
				}
			}
		}
	}
	return results
}

func (f *Fuzzer) subdomain() []string {
	results := []string{}
	for i := 1; i < len(f.Domain)-1; i++ {
		if f.Domain[i] != '-' && f.Domain[i] != '.' && f.Domain[i-1] != '-' && f.Domain[i-1] != '.' {
			results = append(results, f.Domain[:i]+"."+f.Domain[i:])
		}
	}
	return results
}

func (f *Fuzzer) transposition() []string {
	results := []string{}
	for i := 0; i < len(f.Domain)-1; i++ {
		results = append(results, f.Domain[:i]+string(f.Domain[i+1])+string(f.Domain[i])+f.Domain[i+2:])
	}
	return results
}

func (f *Fuzzer) vowelSwap() []string {
	vowels := "aeiou"
	results := []string{}

	for i := 0; i < len(f.Domain); i++ {
		if strings.ContainsRune(vowels, rune(f.Domain[i])) {
			for _, vowel := range vowels {
				results = append(results, f.Domain[:i]+string(vowel)+f.Domain[i+1:])
			}
		}
	}
	return results
}

func (f *Fuzzer) plural() []string {
	results := []string{}
	for i := 2; i < len(f.Domain)-2; i++ {
		suffix := "s"
		if f.Domain[i] == 's' || f.Domain[i] == 'x' || f.Domain[i] == 'z' {
			suffix = "es"
		}
		results = append(results, f.Domain[:i+1]+suffix+f.Domain[i+1:])
	}
	return results
}

func (f *Fuzzer) addition() []string {
	resultSet := make(map[string]bool)

	if strings.Contains(f.Domain, "-") {
		parts := strings.Split(f.Domain, "-")
		for p := 1; p < len(parts); p++ {
			for i := 48; i <= 57; i++ {
				resultSet[strings.Join(parts[:p], "-")+string(rune(i))+"-"+strings.Join(parts[p:], "-")] = true
			}
			for i := 97; i <= 122; i++ {
				resultSet[strings.Join(parts[:p], "-")+string(rune(i))+"-"+strings.Join(parts[p:], "-")] = true
			}
		}
	}

	for i := 48; i <= 57; i++ {
		resultSet[f.Domain+string(rune(i))] = true
	}
	for i := 97; i <= 122; i++ {
		resultSet[f.Domain+string(rune(i))] = true
	}

	results := []string{}
	for r := range resultSet {
		results = append(results, r)
	}
	return results
}

func (f *Fuzzer) dictionary() []string {
	resultSet := make(map[string]bool)

	for _, word := range f.Dictionary {
		if !(strings.HasPrefix(f.Domain, word) && strings.HasSuffix(f.Domain, word)) {
			resultSet[f.Domain+"-"+word] = true
			resultSet[f.Domain+word] = true
			resultSet[word+"-"+f.Domain] = true
			resultSet[word+f.Domain] = true
		}
	}

	if strings.Contains(f.Domain, "-") {
		parts := strings.Split(f.Domain, "-")
		for _, word := range f.Dictionary {
			resultSet[strings.Join(parts[:len(parts)-1], "-")+"-"+word] = true
			resultSet[word+"-"+strings.Join(parts[1:], "-")] = true
		}
	}

	results := []string{}
	for r := range resultSet {
		results = append(results, r)
	}
	return results
}

func (f *Fuzzer) tld() []string {
	results := []string{}
	for _, tld := range f.TLDDictionary {
		if tld != f.TLD {
			results = append(results, tld)
		}
	}
	return results
}

func (f *Fuzzer) Generate(fuzzers []string) {
	f.Domains = NewPermutationSet()

	if len(fuzzers) == 0 || contains(fuzzers, "*original") {
		originalDomain := JoinDomain(f.Subdomain, f.Domain, f.TLD)
		f.Domains.Add(NewPermutation("*original", originalDomain))
	}

	fuzzerMap := map[string]func() []string{
		"addition":      f.addition,
		"bitsquatting":  f.bitsquatting,
		"cyrillic":      f.cyrillic,
		"homoglyph":     f.homoglyph,
		"hyphenation":   f.hyphenation,
		"insertion":     f.insertion,
		"omission":      f.omission,
		"plural":        f.plural,
		"repetition":    f.repetition,
		"replacement":   f.replacement,
		"subdomain":     f.subdomain,
		"transposition": f.transposition,
		"vowel-swap":    f.vowelSwap,
		"dictionary":    f.dictionary,
	}

	defaultFuzzers := []string{
		"addition", "bitsquatting", "cyrillic", "homoglyph", "hyphenation",
		"insertion", "omission", "plural", "repetition", "replacement",
		"subdomain", "transposition", "vowel-swap", "dictionary",
	}

	activeFuzzers := fuzzers
	if len(fuzzers) == 0 {
		activeFuzzers = defaultFuzzers
	}

	for _, fName := range activeFuzzers {
		if fn, ok := fuzzerMap[fName]; ok {
			for _, domain := range fn() {
				fullDomain := JoinDomain(f.Subdomain, domain, f.TLD)
				f.Domains.Add(NewPermutation(fName, fullDomain))
			}
		}
	}

	if len(fuzzers) == 0 || contains(fuzzers, "tld-swap") {
		for _, tld := range f.tld() {
			fullDomain := JoinDomain(f.Subdomain, f.Domain, tld)
			f.Domains.Add(NewPermutation("tld-swap", fullDomain))
		}
	}

	if len(fuzzers) == 0 || contains(fuzzers, "various") {
		if strings.Contains(f.TLD, ".") {
			parts := strings.Split(f.TLD, ".")
			lastPart := parts[len(parts)-1]
			f.Domains.Add(NewPermutation("various", JoinDomain(f.Subdomain, f.Domain, lastPart)))
			f.Domains.Add(NewPermutation("various", JoinDomain(f.Subdomain, f.Domain+f.TLD, "")))
		}
		if !strings.Contains(f.TLD, ".") {
			f.Domains.Add(NewPermutation("various", JoinDomain(f.Subdomain, f.Domain+f.TLD, f.TLD)))
		}
		if f.TLD != "com" && !strings.Contains(f.TLD, ".") {
			f.Domains.Add(NewPermutation("various", JoinDomain(f.Subdomain, f.Domain+"-"+f.TLD, "com")))
			f.Domains.Add(NewPermutation("various", JoinDomain(f.Subdomain, f.Domain+f.TLD, "com")))
		}
		if f.Subdomain != "" {
			f.Domains.Add(NewPermutation("various", JoinDomain("", f.Subdomain+f.Domain, f.TLD)))
			f.Domains.Add(NewPermutation("various", JoinDomain("", strings.ReplaceAll(f.Subdomain, ".", "")+f.Domain, f.TLD)))
			f.Domains.Add(NewPermutation("various", JoinDomain("", f.Subdomain+"-"+f.Domain, f.TLD)))
			f.Domains.Add(NewPermutation("various", JoinDomain("", strings.ReplaceAll(f.Subdomain, ".", "-")+"-"+f.Domain, f.TLD)))
		}
	}

	domainsSlice := f.Domains.ToSlice()
	for _, perm := range domainsSlice {
		encoded, err := IDNAEncode(perm.Domain)
		if err != nil {
			f.Domains.Add(NewPermutation(perm.Fuzzer, ""))
		} else {
			perm.Domain = encoded
		}
	}

	domainsSlice = f.Domains.ToSlice()
	validDomains := NewPermutationSet()
	for _, perm := range domainsSlice {
		if perm.Domain != "" && ValidFQDNRegex.MatchString(perm.Domain) {
			validDomains.Add(perm)
		}
	}
	f.Domains = validDomains
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
