package hashid

import (
	"reflect"
	"testing"
)

func getIds(hi []HashInfo) []HashID {
	var result []HashID
	for i := range hi {
		result = append(result, hi[i].hashID)
	}
	return result
}

func TestIdentify(t *testing.T) {
	tests := []struct {
		name    string
		hash    string
		want    []HashID
		wantErr bool
	}{
		{
			"CRC-16",
			"C061",
			[]HashID{CRC_16, CRC_16_CCITT, FCS_16},
			false,
		},
		{
			"CRC-16",
			"FFFFFFFF",
			[]HashID{Adler_32, CRC_32B, FCS_32, Ghash_32_3, Ghash_32_5, FNV_132, Fletcher_32, Joaat, ELF_32, XOR_32},
			false,
		},
	}

	dp := GetDefaultPrototypes()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Identify([]byte(tt.hash), dp)
			if (err != nil) != tt.wantErr {
				t.Errorf("Identify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			hashIds := getIds(got)
			if !reflect.DeepEqual(hashIds, tt.want) {
				t.Errorf("Identify() = %v, want %v", hashIds, tt.want)
			}
		})
	}
}
