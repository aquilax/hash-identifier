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
