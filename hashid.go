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
			re: regexp.MustCompile("(?i)^[a-f0-9]{4}$"),
			modes: []HashInfo{
				{hashID: CRC_16, name: "CRC-16", extended: false},
				{hashID: CRC_16_CCITT, name: "CRC-16-CCITT", extended: false},
				{hashID: FCS_16, name: "FCS-16", extended: false},
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
