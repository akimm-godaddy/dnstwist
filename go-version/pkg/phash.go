package pkg

import (
	"bytes"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"math"

	"github.com/nfnt/resize"
)

type PHash struct {
	Hash string
}

func NewPHash(imageData []byte, hsize int) (*PHash, error) {
	if hsize == 0 {
		hsize = 8
	}

	img, _, err := image.Decode(bytes.NewReader(imageData))
	if err != nil {
		return nil, err
	}

	grayImg := resize.Resize(uint(hsize), uint(hsize), img, resize.Lanczos3)

	pixels := make([]float64, hsize*hsize)
	bounds := grayImg.Bounds()
	idx := 0
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			r, g, b, _ := grayImg.At(x, y).RGBA()
			gray := 0.299*float64(r) + 0.587*float64(g) + 0.114*float64(b)
			pixels[idx] = gray / 256.0
			idx++
		}
	}

	var avg float64
	for _, p := range pixels {
		avg += p
	}
	avg /= float64(len(pixels))

	hash := ""
	for _, p := range pixels {
		if p > avg {
			hash += "1"
		} else {
			hash += "0"
		}
	}

	return &PHash{
		Hash: hash,
	}, nil
}

func (p *PHash) Compare(other *PHash) int {
	if len(p.Hash) != len(other.Hash) {
		return 0
	}

	bc := len(p.Hash)
	ham := 0
	for i := 0; i < len(p.Hash); i++ {
		if p.Hash[i] != other.Hash[i] {
			ham++
		}
	}

	e := 2.718281828459045
	sub := int((1 + math.Pow(e, float64(bc-ham)/float64(bc)) - e) * 100)
	if sub > 0 {
		return sub
	}
	return 0
}

func (p *PHash) String() string {
	if p.Hash == "" {
		return "0"
	}

	value := int64(0)
	for i := 0; i < len(p.Hash); i++ {
		if p.Hash[i] == '1' {
			value |= (1 << uint(len(p.Hash)-1-i))
		}
	}

	return formatHex(value)
}

func formatHex(n int64) string {
	if n == 0 {
		return "0"
	}

	hexChars := "0123456789abcdef"
	result := ""
	for n > 0 {
		result = string(hexChars[n%16]) + result
		n /= 16
	}
	return result
}
