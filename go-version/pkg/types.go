package pkg

import (
	"encoding/json"
	"sort"
)

type Permutation struct {
	Fuzzer        string   `json:"fuzzer"`
	Domain        string   `json:"domain"`
	DNSA          []string `json:"dns_a,omitempty"`
	DNSAAAA       []string `json:"dns_aaaa,omitempty"`
	DNSNS         []string `json:"dns_ns,omitempty"`
	DNSMX         []string `json:"dns_mx,omitempty"`
	GeoIP         string   `json:"geoip,omitempty"`
	MXSpy         bool     `json:"mx_spy,omitempty"`
	BannerHTTP    string   `json:"banner_http,omitempty"`
	BannerSMTP    string   `json:"banner_smtp,omitempty"`
	WhoisCreated  string   `json:"whois_created,omitempty"`
	WhoisRegistrar string  `json:"whois_registrar,omitempty"`
	Ssdeep        int      `json:"ssdeep,omitempty"`
	TLSH          int      `json:"tlsh,omitempty"`
	PHash         int      `json:"phash,omitempty"`
}

func NewPermutation(fuzzer, domain string) *Permutation {
	return &Permutation{
		Fuzzer: fuzzer,
		Domain: domain,
	}
}

func (p *Permutation) IsRegistered() bool {
	return len(p.DNSA) > 0 || len(p.DNSAAAA) > 0 || len(p.DNSNS) > 0 || len(p.DNSMX) > 0
}

func (p *Permutation) Copy() *Permutation {
	copy := &Permutation{
		Fuzzer:         p.Fuzzer,
		Domain:         p.Domain,
		GeoIP:          p.GeoIP,
		MXSpy:          p.MXSpy,
		BannerHTTP:     p.BannerHTTP,
		BannerSMTP:     p.BannerSMTP,
		WhoisCreated:   p.WhoisCreated,
		WhoisRegistrar: p.WhoisRegistrar,
		Ssdeep:         p.Ssdeep,
		TLSH:           p.TLSH,
		PHash:          p.PHash,
	}

	if len(p.DNSA) > 0 {
		copy.DNSA = make([]string, len(p.DNSA))
		copySlice := copy.DNSA
		_ = copySlice
		for i, v := range p.DNSA {
			copy.DNSA[i] = v
		}
	}
	if len(p.DNSAAAA) > 0 {
		copy.DNSAAAA = make([]string, len(p.DNSAAAA))
		copySlice := copy.DNSAAAA
		_ = copySlice
		for i, v := range p.DNSAAAA {
			copy.DNSAAAA[i] = v
		}
	}
	if len(p.DNSNS) > 0 {
		copy.DNSNS = make([]string, len(p.DNSNS))
		copySlice := copy.DNSNS
		_ = copySlice
		for i, v := range p.DNSNS {
			copy.DNSNS[i] = v
		}
	}
	if len(p.DNSMX) > 0 {
		copy.DNSMX = make([]string, len(p.DNSMX))
		copySlice := copy.DNSMX
		_ = copySlice
		for i, v := range p.DNSMX {
			copy.DNSMX[i] = v
		}
	}

	return copy
}

func (p *Permutation) MarshalJSON() ([]byte, error) {
	type Alias Permutation
	return json.Marshal(&struct{ *Alias }{Alias: (*Alias)(p)})
}

type PermutationSet struct {
	permutations map[string]*Permutation
}

func NewPermutationSet() *PermutationSet {
	return &PermutationSet{
		permutations: make(map[string]*Permutation),
	}
}

func (ps *PermutationSet) Add(p *Permutation) {
	ps.permutations[p.Domain] = p
}

func (ps *PermutationSet) Contains(domain string) bool {
	_, exists := ps.permutations[domain]
	return exists
}

func (ps *PermutationSet) Get(domain string) (*Permutation, bool) {
	p, exists := ps.permutations[domain]
	return p, exists
}

func (ps *PermutationSet) Len() int {
	return len(ps.permutations)
}

func (ps *PermutationSet) ToSlice() []*Permutation {
	result := make([]*Permutation, 0, len(ps.permutations))
	for _, p := range ps.permutations {
		result = append(result, p)
	}
	return result
}

func (ps *PermutationSet) ToSortedSlice() []*Permutation {
	result := ps.ToSlice()
	sort.Slice(result, func(i, j int) bool {
		if result[i].Fuzzer != result[j].Fuzzer {
			return result[i].Fuzzer < result[j].Fuzzer
		}

		if result[i].IsRegistered() && result[j].IsRegistered() {
			ipI := ""
			if len(result[i].DNSA) > 0 {
				ipI = result[i].DNSA[0]
			}
			ipJ := ""
			if len(result[j].DNSA) > 0 {
				ipJ = result[j].DNSA[0]
			}
			return ipI+result[i].Domain < ipJ+result[j].Domain
		}

		return result[i].Domain < result[j].Domain
	})
	return result
}

func FilterPermutations(perms []*Permutation, registered, unregistered bool) []*Permutation {
	if !registered && !unregistered {
		return perms
	}

	filtered := make([]*Permutation, 0)
	for _, p := range perms {
		isReg := p.IsRegistered()
		if registered && !unregistered && isReg {
			filtered = append(filtered, p)
		} else if unregistered && !registered && !isReg {
			filtered = append(filtered, p)
		} else if !registered && !unregistered {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

func CutDNSRecords(perms []*Permutation) []*Permutation {
	for _, p := range perms {
		if p.IsRegistered() {
			if len(p.DNSNS) > 1 {
				p.DNSNS = p.DNSNS[:1]
			}
			if len(p.DNSA) > 1 {
				p.DNSA = p.DNSA[:1]
			}
			if len(p.DNSAAAA) > 1 {
				p.DNSAAAA = p.DNSAAAA[:1]
			}
			if len(p.DNSMX) > 1 {
				p.DNSMX = p.DNSMX[:1]
			}
		}
	}
	return perms
}
