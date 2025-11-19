package pkg

import (
	"github.com/glaslos/ssdeep"
	"github.com/glaslos/tlsh"
)

type LSHType string

const (
	LSHTypeSsdeep LSHType = "ssdeep"
	LSHTypeTLSH   LSHType = "tlsh"
)

func SsdeepHash(data []byte) (string, error) {
	hash, err := ssdeep.FuzzyBytes(data)
	if err != nil {
		return "", err
	}
	return hash, nil
}

func SsdeepCompare(hash1, hash2 string) (int, error) {
	score, err := ssdeep.Distance(hash1, hash2)
	if err != nil {
		return 0, err
	}
	return score, nil
}

func TLSHHash(data []byte) (string, error) {
	hash, err := tlsh.HashBytes(data)
	if err != nil {
		return "", err
	}
	return hash.String(), nil
}

func TLSHCompare(hash1, hash2 string) (int, error) {
	t1, err := tlsh.ParseStringToTlsh(hash1)
	if err != nil {
		return 0, err
	}

	t2, err := tlsh.ParseStringToTlsh(hash2)
	if err != nil {
		return 0, err
	}

	diff := t1.Diff(t2)

	similarity := 100 - (min(diff, 300) / 3)
	return similarity, nil
}

func IsValidSsdeepHash(hash string) bool {
	return hash != "" && hash != "3::"
}

func IsValidTLSHHash(hash string) bool {
	return hash != "" && hash != "TNULL"
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
