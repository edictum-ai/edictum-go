package skill

import "math"

// ShannonEntropy calculates the Shannon entropy of a byte slice.
// Returns bits per byte in the range [0.0, 8.0].
// An empty slice returns 0.0.
func ShannonEntropy(data []byte) float64 {
	n := len(data)
	if n == 0 {
		return 0.0
	}

	var freq [256]int
	for _, b := range data {
		freq[b]++
	}

	length := float64(n)
	entropy := 0.0
	for _, count := range freq {
		if count == 0 {
			continue
		}
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// highEntropyThreshold is the Shannon entropy threshold above which
// a decoded base64 blob is considered suspicious.
const highEntropyThreshold = 5.5
