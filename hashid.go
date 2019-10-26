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
	CRC_32
)

type Prototype struct {
	Re    *regexp.Regexp
	Modes []HashInfo
}

type HashInfo struct {
	ID       HashID
	Hashcat  string
	John     string
	Extended bool
}

var HashNames = map[HashID]string{
	CRC_16:       "CRC-16",
	CRC_16_CCITT: "CRC-16-CCITT",
	FCS_16:       "FCS-16",
	Adler_32:     "Adler-32",
	CRC_32B:      "CRC-32B",
	FCS_32:       "FCS-32",
	Ghash_32_3:   "GHash-32-3",
	Ghash_32_5:   "GHash-32-5",
	FNV_132:      "FNV-132",
	Fletcher_32:  "Fletcher-32",
	Joaat:        "Joaat",
	ELF_32:       "ELF-32",
	XOR_32:       "XOR-32",
	CRC_24:       "CRC-24",
	CRC_32:       "CRC-32",
}

func (hi HashInfo) Name() string {
	return HashNames[hi.ID]
}

func GetDefaultPrototypes() []Prototype {
	return []Prototype{
		{
			regexp.MustCompile("(?i)^[a-f0-9]{4}$"),
			[]HashInfo{
				{ID: CRC_16, Hashcat: "", John: "", Extended: false},
				{ID: CRC_16_CCITT, Hashcat: "", John: "", Extended: false},
				{ID: FCS_16, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{8}$"),
			[]HashInfo{
				{ID: Adler_32, Hashcat: "", John: "", Extended: false},
				{ID: CRC_32B, Hashcat: "", John: "", Extended: false},
				{ID: FCS_32, Hashcat: "", John: "", Extended: false},
				{ID: Ghash_32_3, Hashcat: "", John: "", Extended: false},
				{ID: Ghash_32_5, Hashcat: "", John: "", Extended: false},
				{ID: FNV_132, Hashcat: "", John: "", Extended: false},
				{ID: Fletcher_32, Hashcat: "", John: "", Extended: false},
				{ID: Joaat, Hashcat: "", John: "", Extended: false},
				{ID: ELF_32, Hashcat: "", John: "", Extended: false},
				{ID: XOR_32, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^[a-f0-9]{6}$"),
			[]HashInfo{
				{ID: CRC_24, Hashcat: "", John: "", Extended: false},
			},
		},
		{
			regexp.MustCompile("(?i)^(\\$crc32\\$[a-f0-9]{8}.)?[a-f0-9]{8}$"),
			[]HashInfo{
				{ID: CRC_32, Hashcat: "", John: "crc32", Extended: false},
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
