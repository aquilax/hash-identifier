package hashid

import (
	"regexp"
)

// HashID is a type of hash
type HashID = int

const (
	CRC_16 HashID = 1 + iota
	CRC_16_CCITT
	FCS_16
	Adler_32
	CRC_32B
	FCS_32
	Ghash_32_3
	Ghash_32_5
	FNV_132
	Fletcher_32
	Joaat
	ELF_32
	XOR_32
	CRC_24
)

type Prototype struct {
	Re    *regexp.Regexp
	Modes []HashInfo
}

type HashInfo struct {
	ID       HashID
	Name     string
	Hashcat  *string
	John     *string
	Extended bool
}

func GetDefaultPrototypes() []Prototype {
	return []Prototype{
		{
			regexp.MustCompile("(?i)^[a-f0-9]{4}$"),
			[]HashInfo{
				{ID: CRC_16, Name: "CRC-16", Extended: false},
				{ID: CRC_16_CCITT, Name: "CRC-16-CCITT", Extended: false},
				{ID: FCS_16, Name: "FCS-16", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{8}$"),
			[]HashInfo{
				{ID: Adler_32, Name: "Adler-32", Hashcat: nil, John: nil, Extended: false},
				{ID: CRC_32B, Name: "CRC-32B", Hashcat: nil, John: nil, Extended: false},
				{ID: FCS_32, Name: "FCS-32", Hashcat: nil, John: nil, Extended: false},
				{ID: Ghash_32_3, Name: "GHash-32-3", Hashcat: nil, John: nil, Extended: false},
				{ID: Ghash_32_5, Name: "GHash-32-5", Hashcat: nil, John: nil, Extended: false},
				{ID: FNV_132, Name: "FNV-132", Hashcat: nil, John: nil, Extended: false},
				{ID: Fletcher_32, Name: "Fletcher-32", Hashcat: nil, John: nil, Extended: false},
				{ID: Joaat, Name: "Joaat", Hashcat: nil, John: nil, Extended: false},
				{ID: ELF_32, Name: "ELF-32", Hashcat: nil, John: nil, Extended: false},
				{ID: XOR_32, Name: "XOR-32", Hashcat: nil, John: nil, Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{6}$"),
			[]HashInfo{
				{ID: CRC_24, Name: "CRC-24", Hashcat: nil, John: nil, Extended: false},
			},
		},
	}
}

func Identify(hash []byte, pr []Prototype) ([]HashInfo, error) {
	var i, j int
	var result []HashInfo
	for i = range pr {
		if pr[i].Re.Match(hash) {
			for j = range pr[i].Modes {
				result = append(result, pr[i].Modes[j])
			}
		}
	}
	return result, nil
}
