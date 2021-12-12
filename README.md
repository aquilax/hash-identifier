# hash-identifier

[![Build Status](https://travis-ci.org/aquilax/hash-identifier.svg?branch=master)](https://travis-ci.org/aquilax/hash-identifier) [![GoDoc](https://godoc.org/github.com/aquilax/hash-identifier?status.svg)](https://godoc.org/github.com/aquilax/hash-identifier)

Go package to identify different hashes

Port of [hashId](https://pypi.org/project/hashID/)

## Example usage:


```go
	ids, _ := hashid.Identify([]byte("C061"), hashid.GetDefaultPrototypes())
	for _, hi := range ids {
		fmt.Println(hi.Name())
	}
	// Output:
	// CRC-16
	// CRC-16-CCITT
	// FCS-16
	// Cisco Type 7
```