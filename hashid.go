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
)

type Prototype struct {
	re    *regexp.Regexp
	modes []HashInfo
}

type HashInfo struct {
	hashID   HashID
	name     string
	hashcat  *string
	john     *string
	extended bool
}

func GetDefaultPrototypes() []Prototype {
	return []Prototype{
		{
			regexp.MustCompile("(?i)^[a-f0-9]{4}$"),
			[]HashInfo{
				{hashID: CRC_16, name: "CRC-16", extended: false},
				{hashID: CRC_16_CCITT, name: "CRC-16-CCITT", extended: false},
				{hashID: FCS_16, name: "FCS-16", extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{8}$"),
			[]HashInfo{
				{hashID: Adler_32, name: "Adler-32", hashcat: nil, john: nil, extended: false},
				{hashID: CRC_32B, name: "CRC-32B", hashcat: nil, john: nil, extended: false},
				{hashID: FCS_32, name: "FCS-32", hashcat: nil, john: nil, extended: false},
				{hashID: Ghash_32_3, name: "GHash-32-3", hashcat: nil, john: nil, extended: false},
				{hashID: Ghash_32_5, name: "GHash-32-5", hashcat: nil, john: nil, extended: false},
				{hashID: FNV_132, name: "FNV-132", hashcat: nil, john: nil, extended: false},
				{hashID: Fletcher_32, name: "Fletcher-32", hashcat: nil, john: nil, extended: false},
				{hashID: Joaat, name: "Joaat", hashcat: nil, john: nil, extended: false},
				{hashID: ELF_32, name: "ELF-32", hashcat: nil, john: nil, extended: false},
				{hashID: XOR_32, name: "XOR-32", hashcat: nil, john: nil, extended: false},
			},
		},
	}
}

func Identify(hash []byte, prototypes []Prototype) ([]HashInfo, error) {
	var i, j int
	var result []HashInfo
	for i = range prototypes {
		if prototypes[i].re.Match(hash) {
			for j = range prototypes[i].modes {
				result = append(result, prototypes[i].modes[j])
			}
		}
	}
	return result, nil
}
