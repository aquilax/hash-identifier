package hashid_test

import (
	"fmt"

	hashid "github.com/aquilax/hash-identifier"
)

func ExampleIdentify() {
	ids, _ := hashid.Identify([]byte("C061"), hashid.GetDefaultPrototypes())
	for _, hi := range ids {
		fmt.Println(hi.Name())
	}
	// Output:
	// CRC-16
	// CRC-16-CCITT
	// FCS-16
	// Cisco Type 7
}
